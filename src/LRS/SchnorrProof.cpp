
#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/ECParams.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "SchnorrProof.hpp"

using Dissent::Crypto::AbstractGroup::CppECGroup;
using Dissent::Crypto::AbstractGroup::ECParams;
using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {

  SchnorrProof::SchnorrProof(QByteArray context) :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _context(context),
    _witness(_group->RandomExponent()),
    _witness_image(_group->Exponentiate(_group->GetGenerator(), _witness)),
    _tag_generator(_group->HashIntoElement(context)),
    _linkage_tag(_group->Exponentiate(_tag_generator, _witness))
  {
    SetWitness(_witness.GetByteArray());
    SetWitnessImage(_group->ElementToByteArray(_witness_image));
    SetLinkageTag(_group->ElementToByteArray(_linkage_tag));
  }

  SchnorrProof::SchnorrProof(QByteArray context,
          QByteArray witness, 
          QByteArray witness_image) :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _context(context),
    _witness_image(_group->ElementFromByteArray(witness_image)),
    _tag_generator(_group->HashIntoElement(context)),
    _linkage_tag(_group->Exponentiate(_tag_generator, _witness))
  {
    SetWitness(witness); 
    SetWitnessImage(witness_image); 
    SetLinkageTag(_group->ElementToByteArray(_linkage_tag)); 
  }

  SchnorrProof::SchnorrProof(QByteArray context,
      QByteArray witness_image,
      QByteArray linkage_tag,
      QByteArray commit, 
      QByteArray challenge, 
      QByteArray response) :
    SigmaProof(ProofType_SchnorrProof),
    _group(CppECGroup::GetGroup(ECParams::NIST_P192)),
    _context(context),
    _witness_image(_group->ElementFromByteArray(witness_image)),
    _tag_generator(_group->HashIntoElement(context)),
    _linkage_tag(_group->ElementFromByteArray(linkage_tag)),
    _challenge(challenge),
    _response(response)
  {
    QDataStream stream(commit);

    QByteArray bytes_1, bytes_2;
    stream >> bytes_1 >> bytes_2;
    _commit_1 = _group->ElementFromByteArray(bytes_1);
    _commit_2 = _group->ElementFromByteArray(bytes_2);

    SetWitnessImage(witness_image);
    SetLinkageTag(linkage_tag);
    SetChallenge(_challenge);
    SetResponse(response);
    SetCommit(commit);
  }

  SchnorrProof::~SchnorrProof() {};

  void SchnorrProof::GenerateCommit()
  {
    // v = random integer
    // t = g^v
    _commit_secret = _group->RandomExponent();
    _commit_1 = _group->Exponentiate(_group->GetGenerator(), _commit_secret);
    _commit_2 = _group->Exponentiate(_tag_generator, _commit_secret);

    SetCommit(CommitBytes(_commit_1, _commit_2));
  };

  void SchnorrProof::GenerateChallenge()
  {
    _challenge = CommitHash();
    SetChallenge(_challenge);
  }

  void SchnorrProof::Prove(QByteArray challenge)
  {
    const Integer e = _group->RandomExponent();
    const QByteArray e_bytes = e.GetByteArray();
    const int e_orig_len = e_bytes.count();

    if(e_bytes.count() <= challenge.count())
      qFatal("Challenge is bigger than group order");

    // Replace the rightmost bytes of e with the challenge
    const QByteArray final = e_bytes.left(e_bytes.count() - challenge.count()) + challenge;

    Q_ASSERT(e_orig_len == final.count());

    _challenge = Integer(final);  
    SetChallenge(_challenge);
    Prove();
  }

  void SchnorrProof::Prove()
  {
    Q_ASSERT(_witness > 0);
    Q_ASSERT(_commit_secret > 0);
    Q_ASSERT(_challenge > 0);

    // r = v - cx
    _response = (_commit_secret - 
        (_witness.MultiplyMod(_challenge, _group->GetOrder()))) % _group->GetOrder();
    SetResponse(_response.GetByteArray());
  }

  void SchnorrProof::FakeProve()
  {
    // pick c, r at random
    _challenge = _group->RandomExponent();
    _response = _group->RandomExponent();

    // fake the first commit
    _commit_1 = _group->Exponentiate(_witness_image, _challenge);
    const Element tmp_1 = _group->Exponentiate(_group->GetGenerator(), _response);
    // commit = (g^r) * (g^x)^c
    _commit_1 = _group->Multiply(tmp_1, _commit_1);

    // fake the second commit
    _commit_2 = _group->Exponentiate(_linkage_tag, _challenge);
    const Element tmp_2 = _group->Exponentiate(_tag_generator, _response);
    // commit = (g^r) * (g^x)^c
    _commit_2 = _group->Multiply(tmp_2, _commit_2);

    // When we're fake proving, we have no commit secret and no witness
    _commit_secret = 0;
    _witness = 0;

    qDebug() << "t1" << _group->ElementToByteArray(_commit_1).toHex();
    qDebug() << "t2" << _group->ElementToByteArray(_commit_2).toHex();
    qDebug() << "c" << _challenge.GetByteArray().toHex();
    qDebug() << "r" << _response.GetByteArray().toHex();

    SetCommit(CommitBytes(_commit_1, _commit_2));
    SetChallenge(_challenge);
    SetResponse(_response.GetByteArray());
  }

  bool SchnorrProof::Verify(bool verify_challenge) const 
  {
    // (g^x)^c
    Element tmp_1 = _group->Exponentiate(_witness_image, _challenge);
    Element tmp_2 = _group->Exponentiate(_linkage_tag, _challenge);

    // g^r
    Element out_1 = _group->Exponentiate(_group->GetGenerator(), _response);
    Element out_2 = _group->Exponentiate(_tag_generator, _response);

    // g^{r + cx} -- should equal g^{v}
    out_1 = _group->Multiply(tmp_1, out_1);
    out_2 = _group->Multiply(tmp_2, out_2);

    // if verify_challenge is set, make sure that challenge is
    // a hash of the commit 
    if(verify_challenge && _challenge != CommitHash()) {
      qDebug() << "Challenge mismatch";
      return false;
    }

    qDebug() << "o1" << _group->ElementToByteArray(out_1).toHex();
    qDebug() << "o2" << _group->ElementToByteArray(out_2).toHex();

    if(out_1 != _commit_1) {
      qDebug() << "Commit 1 failed"; 
      return false;
    }

    if(out_2 != _commit_2) {
      qDebug() << "Commit 2 failed"; 
      return false;
    }

    return true;
  };

  Integer SchnorrProof::CommitHash() const 
  {
    Hash *hash = CryptoFactory::GetInstance().GetLibrary()->GetHashAlgorithm();
    hash->Restart();

    // Hash group definition 
    hash->Update(_group->GetByteArray());
    hash->Update(_group->ElementToByteArray(_group->GetGenerator()));
    hash->Update(_context);
    hash->Update(_group->ElementToByteArray(_tag_generator));
    hash->Update(_group->ElementToByteArray(_witness_image));
    hash->Update(_group->ElementToByteArray(_linkage_tag));
    hash->Update(_group->ElementToByteArray(_commit_1));
    hash->Update(_group->ElementToByteArray(_commit_2));

    qDebug() << "g" << _group->ElementToByteArray(_group->GetGenerator()).toHex();
    qDebug() << "wi" << _group->ElementToByteArray(_witness_image).toHex();
    qDebug() << "commit_1" << _group->ElementToByteArray(_commit_1).toHex();
    qDebug() << "commit_2" << _group->ElementToByteArray(_commit_2).toHex();

    return Integer(hash->ComputeHash()) % _group->GetOrder();
  }

  QByteArray SchnorrProof::CommitBytes(Element commit_1, Element commit_2) const
  {
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);

    const QByteArray bytes_1 = _group->ElementToByteArray(commit_1);
    const QByteArray bytes_2 = _group->ElementToByteArray(commit_2);
    stream << bytes_1 << bytes_2;

    return out;

  }
}
}
