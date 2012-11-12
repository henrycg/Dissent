
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include "Crypto/AbstractGroup/CompositeIntegerGroup.hpp"
#include "Crypto/CppIntegerData.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "FactorProof.hpp"

using Dissent::Crypto::AbstractGroup::CompositeIntegerGroup;
using Dissent::Crypto::CppIntegerData;
using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;
using Dissent::Utils::Random;

namespace Dissent {
namespace LRS {

  FactorProof::FactorProof(int n_bits, QByteArray context) :
    SigmaProof(ProofType_FactorProof),
    _context(context)
  {
    CryptoPP::AutoSeededX917RNG<CryptoPP::AES> rng;
    CryptoPP::InvertibleRSAFunction rsa;

    // RSA encryption exponent is 3
    rsa.Initialize(rng, n_bits, CryptoPP::Integer(RsaEncryptionExponent));

    Integer n(new CppIntegerData(rsa.GetModulus()));
    _group = QSharedPointer<CompositeIntegerGroup>(new CompositeIntegerGroup(n));

    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    QByteArray digest = hash->ComputeHash(context);

    // m is in range [0,n)
    const Integer m = Integer(digest) % n;

    // g^m mod P
    _witness_image = _group->Exponentiate(_group->GetGenerator(), m);
    SetWitnessImage(WitnessImageBytes());

    // root = m^{1/e}
    CryptoPP::Integer crypto_m(("0x" + m.GetByteArray().toHex()).constData());
    //Q_ASSERT(crypto_m > 0);

    const CryptoPP::Integer root = rsa.CalculateInverse(rng, crypto_m);
    //Q_ASSERT(root > 0);

    //Q_ASSERT(crypto_m == a_exp_b_mod_c(root, 3, rsa.GetModulus()));
    //Q_ASSERT(crypto_m == ((root*root*root) % rsa.GetModulus()));

    // witness (m) is h^{1/e} mod n
    _witness = Integer(new CppIntegerData(root));
    SetWitness(_witness.GetByteArray());

    /*
    qDebug() << "_witness" << _witness.GetByteArray().toHex();
    qDebug() << "_n" << n.GetByteArray().toHex();
    qDebug() << "m" << m.GetByteArray().toHex();
    qDebug() << "w3" << ((_witness*_witness*_witness)%n).GetByteArray().toHex();
    */

    // tag = g^m
    _linkage_tag = _group->Exponentiate(_group->GetGenerator(), _witness);
    SetLinkageTag(_group->ElementToByteArray(_linkage_tag));

    _g1 = _linkage_tag;
    _g2 = _group->Exponentiate(_g1, _witness);
    _g3 = _witness_image;
  }

  FactorProof::FactorProof(QByteArray context,
          QByteArray witness, 
          QByteArray witness_image) :
    SigmaProof(ProofType_FactorProof),
    _context(context),
    _witness(witness)
  {
    QDataStream stream(witness_image);
    QByteArray n_bytes, wi_bytes;
    stream >> n_bytes >> wi_bytes;

    _group = QSharedPointer<CompositeIntegerGroup>(new CompositeIntegerGroup(Integer(n_bytes)));

    SetWitness(witness);

    _witness_image = _group->ElementFromByteArray(wi_bytes);
    SetWitnessImage(WitnessImageBytes());

    _linkage_tag = _group->Exponentiate(_group->GetGenerator(), _witness);
    SetLinkageTag(_group->ElementToByteArray(_linkage_tag));

    _g1 = _linkage_tag;
    _g2 = _group->Exponentiate(_g1, _witness);
    _g3 = _witness_image;
  }

  FactorProof::FactorProof(QByteArray context,
      QByteArray witness_image,
      QByteArray linkage_tag, 
      QByteArray commit, 
      QByteArray challenge, 
      QByteArray response) :
    SigmaProof(ProofType_FactorProof),
    _context(context),
    _challenge(challenge),
    _response(response)
  {
    SetWitnessImage(witness_image);
    SetLinkageTag(linkage_tag);
    SetCommit(commit);
    SetChallenge(_challenge);
    SetResponse(response);

    QDataStream w_stream(witness_image);
    QByteArray n_bytes, wi_bytes;
    w_stream >> n_bytes >> wi_bytes;

    _group = QSharedPointer<CompositeIntegerGroup>(new CompositeIntegerGroup(Integer(n_bytes)));
    _witness_image = _group->ElementFromByteArray(wi_bytes);
    _linkage_tag = _group->ElementFromByteArray(linkage_tag);

    QByteArray c1_bytes, c2_bytes;
    QDataStream c_stream(commit);
    c_stream >> c1_bytes >> c2_bytes;

    _commit_1 = _group->ElementFromByteArray(c1_bytes);
    _commit_2 = _group->ElementFromByteArray(c2_bytes);

    _g1 = _linkage_tag;
    _g2 = _group->RandomElement();
    _g3 = _witness_image;


    qDebug() << "Unserialized......";
    qDebug() << "_witness_image" << _group->ElementToByteArray(_witness_image).toHex();
    qDebug() << "_linkage_tag" << _group->ElementToByteArray(_linkage_tag).toHex();
    qDebug() << "_commit_1" << _group->ElementToByteArray(_commit_1).toHex();
    qDebug() << "_commit_2" << _group->ElementToByteArray(_commit_2).toHex();
  }

  FactorProof::~FactorProof() {};

  void FactorProof::GenerateCommit()
  {
    // pick random exponent r in [0, n)
    _commit_secret = _group->RandomExponent();

    // t1 = (g1)^r
    _commit_1 = _group->Exponentiate(_g1, _commit_secret);

    // t2 = (g2)^r 
    _commit_2 = _group->Exponentiate(_g2, _commit_secret);

    SetCommit(CommitBytes());
  }

  void FactorProof::GenerateChallenge()
  {
    _challenge = CommitHash();
    SetChallenge(_challenge);
  }

  void FactorProof::Prove(QByteArray challenge)
  {
    if(Integer(challenge) >= _group->GetOrder()) {
      qFatal("Challenge too big");
    } 

    const Integer e = _group->RandomExponent();
    const QByteArray e_bytes = e.GetByteArray();

    // Replace the rightmost bytes of e with the challenge
    _challenge = Integer(e_bytes.left(e_bytes.count() - challenge.count()) + challenge);
    SetChallenge(_challenge);

    Prove();
  }

  void FactorProof::Prove()
  {
    /*
    const Integer n = _witness_image;
    const Integer p = _witness;
    const Integer q = n / p; // n = p*q
    const Integer phi_n = (p - 1) * (q - 1);
    */

    // r = s - cx
    _response = (_commit_secret - (_challenge * _witness)) % _group->GetOrder();
    SetResponse(_response.GetByteArray());
  }

  void FactorProof::FakeProve()
  {
    // c = random
    _challenge = _group->RandomExponent();
    // r = random
    _response = _group->RandomExponent();

    // t1 = (g1^r)*(y1)^c == (g^r)*(tag^c)
    _commit_1 = _group->CascadeExponentiate(_g1, _response, _g2, _challenge);

    // t2 = (g2^r)*(y2)^c == (g^m)^r * (tag)^{mc}
    _commit_2 = _group->CascadeExponentiate(_g2, _response, _g3, _challenge);

    // When we're fake proving, we have no commit secret and no witness
    _commit_secret = 0;
    _witness = 0;

    SetChallenge(_challenge);
    SetResponse(_response.GetByteArray());
    SetCommit(CommitBytes());
  }

  bool FactorProof::Verify(bool verify_challenge) const 
  {
    PrintDebug();

    // check_1 = (g1^r)*(g2)^c
    Element check_1 = _group->CascadeExponentiate(_g1, _response, _g2, _challenge);

    // check_2 = (g2^r)*(g3)^c
    Element check_2 = _group->CascadeExponentiate(_g2, _response, _g3, _challenge);

    if(check_1 != _commit_1) {
      qDebug() << "Commit 1 failed";
      return false;
    }

    if(check_2 != _commit_2) {
      qDebug() << "Commit 2 failed";
      return false;
    }

    // if verify_challenge is set, make sure that challenge is
    // a hash of the commit 
    if(verify_challenge && _challenge != CommitHash()) {
      qDebug() << "Challenge does not match commit hash"; 
      return false;
    }
    return true;
  };

  Integer FactorProof::CommitHash() const 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->ElementToByteArray(_witness_image));
    hash->Update(_group->ElementToByteArray(_linkage_tag));
    hash->Update(_group->ElementToByteArray(_g1));
    hash->Update(_group->ElementToByteArray(_g2));
    hash->Update(_group->ElementToByteArray(_g3));
    hash->Update(_group->ElementToByteArray(_commit_1));
    hash->Update(_group->ElementToByteArray(_commit_2));

    // Value of hash mod group order
    return Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  QByteArray FactorProof::CommitBytes() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << _group->ElementToByteArray(_commit_1);
    stream << _group->ElementToByteArray(_commit_2);
    return out;
  }

  void FactorProof::PrintDebug() const
  {
    qDebug() << "_g1" << _group->ElementToByteArray(_g1).toHex();
    qDebug() << "_g2" << _group->ElementToByteArray(_g2).toHex();
    qDebug() << "_g3" << _group->ElementToByteArray(_g3).toHex();
    qDebug() << "_linkage_tag" << _group->ElementToByteArray(_linkage_tag).toHex();
    qDebug() << "_commit_1" << _group->ElementToByteArray(_commit_1).toHex();
    qDebug() << "_commit_2" << _group->ElementToByteArray(_commit_2).toHex();
    qDebug() << "_challenge" << _challenge.GetByteArray().toHex();
    qDebug() << "_response" << _response.GetByteArray().toHex();
  }
  
  QByteArray FactorProof::WitnessImageBytes() const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    stream << _group->GetOrder().GetByteArray();
    stream << _group->ElementToByteArray(_witness_image);

    return out;
  }

}
}
