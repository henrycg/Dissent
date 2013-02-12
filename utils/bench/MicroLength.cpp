#include <QDateTime>
#include "Benchmark.hpp"

namespace Dissent {
namespace Benchmarks {

  const char header[] =  ", n_gen, n_verify, n_client, n_server, "
                          "proof type, nbits, group type, nelms, "
                          "plaintext bytes, ciphertext len, time gen n, "
                          "time verify n";
  typedef struct {
    int n_clients;
    int n_servers;
    int n_gen;
    int n_verify;
    // if true, vary number of ciphertext
    // elements, else leave it at the 
    bool vary_n_elms;
  } verifyN_params;

  typedef struct {
    // proof type
    // group type
    // nelms
    // plaintext bytes per elm
    // ciphertext len
    int cipher_len;
    // time generate M
    double time_gen;
    // time verify N 
    double time_verify;
  } verifyN_stats;

  void ComputeSecrets(QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PrivateKey> > &client_sks_in,
      const QList<QSharedPointer<const PrivateKey> > &server_sks_in,
      const QList<QSharedPointer<const PublicKey> > &client_pks_in,
      const QList<QSharedPointer<const PublicKey> > &server_pks_in,
      QList<QSharedPointer<const PrivateKey> > &client_sks_out,
      QList<QSharedPointer<const PrivateKey> > &server_sks_out,
      QList<QSharedPointer<const PublicKey> > &client_pks_out,
      QList<QSharedPointer<const PublicKey> > &server_pks_out)
  {
    Parameters::ProofType t = params->GetProofType();
    if(t == Parameters::ProofType_HashingGenerator) {
    // If we're using hashed, we have to use pre-computed shared secrets
      for(int i=0; i<client_sks_in.count(); i++) { 
        QSharedPointer<const PrivateKey> priv;
        QSharedPointer<const PublicKey> pub;
        QList<QSharedPointer<const PublicKey> > commits;
        BlogDropUtils::GetMasterSharedSecrets(params, 
            client_sks_in[i], server_pks_in, priv, pub, commits);

        client_pks_out.append(pub);
        client_sks_out.append(priv);
      }

      for(int i=0; i<server_sks_in.count(); i++) { 
        QSharedPointer<const PrivateKey> priv;
        QSharedPointer<const PublicKey> pub;
        QList<QSharedPointer<const PublicKey> > commits;
        BlogDropUtils::GetMasterSharedSecrets(params, 
            server_sks_in[i], client_pks_in, priv, pub, commits);

        server_pks_out.append(pub);
        server_sks_out.append(priv);
      }

    } else if(t == Parameters::ProofType_ElGamal 
        || t == Parameters::ProofType_Pairing 
        || t == Parameters::ProofType_Xor) {
    // If we're using ElGamal, we don't need extra shared secrets
      client_sks_out = client_sks_in;
      server_sks_out = server_sks_in;
      client_pks_out = client_pks_in;
      server_pks_out = server_pks_in;
    } else {
      qFatal("Unknown proof type");
    }
  }

  // Verify N proofs
  // Print ciphertext size
  void VerifyNTimes(QSharedPointer<Parameters> params, 
      verifyN_params *p, verifyN_stats *s)
  {
    const int nclients = p->n_clients;
    const int nservers = p->n_servers;
    const int author_idx = 1;

    // Generate an author PK
    const QSharedPointer<const PrivateKey> author_priv(new PrivateKey(params));
    const QSharedPointer<const PublicKey> author_pk(new PublicKey(author_priv));

    // Generate list of server pks
    QList<QSharedPointer<const PublicKey> > server_pks;
    QList<QSharedPointer<const PrivateKey> > server_sks;

    for(int i=0; i<nservers; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      server_sks.append(priv);
      server_pks.append(pub);
    }

    // Generate list of client pks
    QList<QSharedPointer<const PublicKey> > client_pks;
    QList<QSharedPointer<const PrivateKey> > client_sks;
    for(int i=0; i<nclients; i++) {
      QSharedPointer<const PrivateKey> priv(new PrivateKey(params));
      QSharedPointer<const PublicKey> pub(new PublicKey(priv));
      client_sks.append(priv);
      client_pks.append(pub);
    }

    // for each server/client
    QList<QSharedPointer<const PrivateKey> > master_client_sks;
    QList<QSharedPointer<const PublicKey> > master_client_pks;
    QList<QSharedPointer<const PrivateKey> > master_server_sks;
    QList<QSharedPointer<const PublicKey> > master_server_pks;

    ComputeSecrets(params,
        client_sks, server_sks, 
        client_pks, server_pks,
        master_client_sks, master_server_sks, 
        master_client_pks, master_server_pks);

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, server_pks));
   
    ///// Loop here
    int nelms = 1;
    while(Plaintext::CanFit(params)<1024*4) {  
      if(p->vary_n_elms) {
        params->SetNElements(nelms);
      }

      // Get a random plaintext
      Library *lib = CryptoFactory::GetInstance().GetLibrary();
      QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

      BlogDropAuthor auth(params, master_client_sks[author_idx], server_pk_set, author_priv);

      QByteArray msg(auth.MaxPlaintextLength(), 0);
      rand->GenerateBlock(msg);

      BlogDropServer server(params, master_server_sks[0], server_pk_set, author_pk);

      // Generate client ciphertext and give it to all servers
      QByteArray c;
      
      qint64 start, end; 
      
      start = QDateTime::currentMSecsSinceEpoch();
      for(int i=0; i<p->n_gen; i++) {
        // Change the round nonce to make sure things are randomized
        params->SetRoundNonce(QString("%0 %1 %2").arg(i).arg(nelms).arg(QString(author_pk->GetByteArray())).toAscii());

        c = BlogDropClient(params, master_client_sks[0], server_pk_set, 
            author_pk).GenerateCoverCiphertext();
      }
      end = QDateTime::currentMSecsSinceEpoch();
      s->time_gen = (end-start)/1000.0;

      start = QDateTime::currentMSecsSinceEpoch();
      for(int i=0; i<p->n_verify; i++) {
        server.AddClientCiphertext(c, master_client_pks[0], true);
      }
      end = QDateTime::currentMSecsSinceEpoch();

      s->time_verify = (end-start)/1000.0;
      s->cipher_len = c.count();

      qDebug() << ","
        << p->n_gen << "," 
        << p->n_verify << "," 
        << p->n_clients << "," 
        << p->n_servers << "," 
        << Parameters::ProofTypeToString(params->GetProofType()) << ","
        << params->GetKeyGroup()->GetSecurityParameter() << ","
        << params->GetKeyGroup()->ToString() << "," 
        << params->GetNElements() << ","
        << Plaintext::CanFit(params) << ","
        << s->cipher_len << ","
        << s->time_gen << ","
        << s->time_verify << ",";

      // If we're not varying the number of elements,
      // stop here
      if(!p->vary_n_elms) break;

      if(nelms < 8) nelms += 1;
      else if(nelms < 16) nelms += 2;
      else if(nelms < 32) nelms += 4;
      else if(nelms < 64) nelms += 8;
      else if(nelms < 128) nelms += 16;
      else if(nelms < 256) nelms += 32;
      else if(nelms < 512) nelms += 64;
      else nelms += 128;
    }
  }

  // Given parameters, change message lengths
  void VerifyNTimesDiffLen(QSharedPointer<Parameters> params, verifyN_params *p)
  {
    verifyN_stats s;
   
    VerifyNTimes(params, p, &s);

    // proof type
    // nbits
    // group type
    // nelms
    // plaintext bytes 
    // ciphertext len
    // time verify N
  }

  // Cycle through proof types
  void VerifyNTimesDiffLenLibrary(verifyN_params *p, bool use_openssl)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(use_openssl ? CryptoFactory::OpenSSL : CryptoFactory::CryptoPP);
 
    // paring
    VerifyNTimesDiffLen(Parameters::PairingProduction(), p);
     

    // hashing
      // integer
    VerifyNTimesDiffLen(Parameters::IntegerHashingProduction(), p);
   
    
      // open ec
    VerifyNTimesDiffLen(Parameters::OpenECHashingProduction(), p);
      // cpp ec
    VerifyNTimesDiffLen(Parameters::CppECHashingProduction(), p);
      // cpp ec
    VerifyNTimesDiffLen(Parameters::BotanECHashingProduction(), p);
    
    // elgamal
      // integer
    VerifyNTimesDiffLen(Parameters::IntegerElGamalProduction(), p);

    
      // open ec
    VerifyNTimesDiffLen(Parameters::OpenECElGamalProduction(), p);
      // cpp ec
    VerifyNTimesDiffLen(Parameters::CppECElGamalProduction(), p);
      // cpp ec
    VerifyNTimesDiffLen(Parameters::BotanECElGamalProduction(), p);

      // Xor
    VerifyNTimesDiffLen(Parameters::XorTesting(), p);
    
    cf.SetLibrary(cname);
  }

  // Cycle through security parameters
  void VerifyNTimesDiffLenSecurity(verifyN_params *p)
  {
    QList<QSharedPointer<Parameters> > params;

    // integer
    for(int i=0; i<IntegerGroup::INVALID; i++) {
      QSharedPointer<IntegerGroup> g = IntegerGroup::GetGroup((IntegerGroup::GroupSize)i);

      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_ElGamal, QByteArray(), g, g, 1)));
      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_HashingGenerator, QByteArray(), g, g, 1)));
    }

    // cpp ec
    for(int i=0; i<ECParams::INVALID; i++) {
      QSharedPointer<CppECGroup> g = CppECGroup::GetGroup((ECParams::CurveName)i);

      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_ElGamal, QByteArray(), g, g, 1)));
      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_HashingGenerator, QByteArray(), g, g, 1)));
    }

    // botan ec
    for(int i=0; i<ECParams::INVALID; i++) {
      QSharedPointer<BotanECGroup> g = BotanECGroup::GetGroup((ECParams::CurveName)i);

      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_ElGamal, QByteArray(), g, g, 1)));
      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_HashingGenerator, QByteArray(), g, g, 1)));
    }

    // open ec
    for(int i=0; i<ECParams::INVALID; i++) {
      QSharedPointer<OpenECGroup> g = OpenECGroup::GetGroup((ECParams::CurveName)i);

      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_ElGamal, QByteArray(), g, g, 1)));
      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_HashingGenerator, QByteArray(), g, g, 1)));
    }

    // pairing
    for(int i=0; i<PairingGroup::INVALID; i++) {
      QSharedPointer<PairingG1Group> g1 = PairingG1Group::GetGroup((PairingGroup::GroupSize)i);
      QSharedPointer<PairingGTGroup> gt = PairingGTGroup::GetGroup((PairingGroup::GroupSize)i);

      params.append(QSharedPointer<Parameters>(new 
            Parameters(Parameters::ProofType_Pairing, QByteArray(), g1, gt, 1)));
    }

    for(int i=0; i<params.count(); i++) {
      VerifyNTimesDiffLen(params[i], p);
    }
  }

  // Cycle through proof types
  void VerifyNTimesDiffLenXor(verifyN_params *p, bool use_openssl)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::LibraryName cname = cf.GetLibraryName();
    cf.SetLibrary(use_openssl ? CryptoFactory::OpenSSL : CryptoFactory::CryptoPP);

      // open ec
    //VerifyNTimesDiffLen(Parameters::OpenECHashingProduction(), p);

      // Xor
    VerifyNTimesDiffLen(Parameters::XorTesting(), p);
    cf.SetLibrary(cname);
  }

  // Cycle through integer types
  TEST(Micro, VaryLength) {

    verifyN_params p;
    p.n_servers = 16;
    p.n_clients = 1024;
    p.n_gen = 32;
    p.n_verify = 32;
    p.vary_n_elms = true;

    qDebug() << header;
    VerifyNTimesDiffLenLibrary(&p, false);
  }

  // Vary number of servers
  TEST(Micro, VaryNServers) {

    verifyN_params p;
    p.n_servers = 16;
    p.n_clients = 1024;
    p.n_gen = 32;
    p.n_verify = 32;
    p.vary_n_elms = false;

    qDebug() << header;

    for(int i=2; i<128;) {
      p.n_servers = i;
      VerifyNTimesDiffLenLibrary(&p, false);

      if(i < 8) i += 1;
      else if(i < 16) i += 2;
      else if(i < 32) i += 4;
      else if(i < 64) i += 8;
      else if(i < 128) i += 16;
      else i += 128;
    }
  }

  // Vary number of clients
  TEST(Micro, VaryNClients) {

    verifyN_params p;
    p.n_servers = 16;
    p.n_clients = 1024;
    p.n_gen = 32;
    p.n_verify = 32;
    p.vary_n_elms = false;

    qDebug() << header;

    for(int i=8; i<8192;) {
      p.n_clients = i;
      VerifyNTimesDiffLenLibrary(&p, false);

      if(i < 8) i += 4;
      else if(i < 16) i += 8;
      else if(i < 32) i += 16;
      else if(i < 64) i += 32;
      else if(i < 128) i += 64;
      else if(i < 256) i += 128;
      else if(i < 512) i += 256;
      else if(i < 1024) i += 512;
      else if(i < 2048) i += 1024;
      else if(i < 4096) i += 2048;
      else i += 4096;
    }
  }

  /*
  // Vary number of clients
  TEST(Micro, XorVaryNClients) {

    verifyN_params p;
    p.n_servers = 10;
    p.n_clients = 1000;
    p.n_gen = 10;
    p.n_verify = 10;
    p.vary_n_elms = false;

    qDebug() << header;

    for(int i=2; i<4096;) {
      p.n_clients = i;
      VerifyNTimesDiffLenXor(&p, false);

      if(i < 8) i += 1;
      else if(i < 16) i += 2;
      else if(i < 32) i += 4;
      else if(i < 64) i += 8;
      else if(i < 128) i += 16;
      else if(i < 256) i += 32;
      else if(i < 512) i += 64;
      else if(i < 1024) i += 128;
      else if(i < 2048) i += 256;
      else if(i < 4096) i += 512;
      else i += 1024;
    }
  }
  */

  // Cycle through integer types
  TEST(Micro, VarySecurity) {

    verifyN_params p;
    p.n_servers = 16;
    p.n_clients = 1024;
    p.n_gen = 32;
    p.n_verify = 32;
    p.vary_n_elms = false;

    qDebug() << header;
    VerifyNTimesDiffLenSecurity(&p);
  }

}
}
