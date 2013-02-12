#include <QDateTime>
#include <cryptopp/nbtheory.h>
#include "Benchmark.hpp"

namespace Dissent {
namespace Benchmarks {

  // Cycle through integer types
  TEST(DropOff, Client1MB) {
    QSharedPointer<Parameters> params(Parameters::OpenECHashingProduction());

    const int nclients = 256;
    const int nservers = 16;
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
    while(Plaintext::CanFit(params)<1024*1024) {  
      params->SetNElements(params->GetNElements()+1);
    }

    qDebug() << "nelms" << params->GetNElements();

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

    c = BlogDropClient(params, master_client_sks[0], server_pk_set, 
        author_pk).GenerateCoverCiphertext();
    end = QDateTime::currentMSecsSinceEpoch();
    qDebug() << "time_gen_1" << (end-start)/1000.0;

    start = QDateTime::currentMSecsSinceEpoch();
    for(int i=0; i<nclients; i++) {
      server.AddClientCiphertext(c, master_client_pks[0], true);  
      end = QDateTime::currentMSecsSinceEpoch();
      qDebug() << "time_verify" << i << (end-start)/1000.0;
    }
    end = QDateTime::currentMSecsSinceEpoch();

    qDebug() << "time_verify_N" << (end-start)/1000.0;

    /*
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
      */
  }

}
}
