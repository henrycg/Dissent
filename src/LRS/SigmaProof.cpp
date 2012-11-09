
#include "SigmaProof.hpp"
#include "Crypto/CryptoFactory.hpp"

using Dissent::Crypto::Hash;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace LRS {
  SigmaProof::SigmaProof(ProofType type) :
        _type(type),
        _have_witness(false),
        _have_witness_image(false),
        _have_commit(false),
        _have_challenge(false),
        _have_response(false)
      {}

  QVariant SigmaProof::IntegerToVariant(Integer i) const
  {
    return QVariant(i.GetByteArray());
  }

  Integer SigmaProof::VariantToInteger(QVariant v) const
  {
    return Integer(v.toByteArray());
  }

  QByteArray SigmaProof::GetWitness() const
  {
    if(!_have_witness) qFatal("Witness not set");
    return _witness;
  }
  
  void SigmaProof::SetWitness(QByteArray witness) 
  {
    _have_witness = true;
    _witness = witness;
  }

  QByteArray SigmaProof::GetWitnessImage() const
  {
    if(!_have_witness_image) qFatal("Witness image not set");
    return _witness_image;
  }

  void SigmaProof::SetWitnessImage(QByteArray witness_image) 
  {
    _have_witness_image = true;
    _witness_image = witness_image;
  }

  QByteArray SigmaProof::GetLinkageTag() const
  {
    if(!_have_linkage_tag) qFatal("Linkage tag not set");
    return _linkage_tag;
  }

  void SigmaProof::SetLinkageTag(QByteArray linkage_tag) 
  {
    _have_linkage_tag = true;
    _linkage_tag = linkage_tag;
  }

  QByteArray SigmaProof::GetCommit() const
  {
    if(!_have_commit) qFatal("Commit not set");
    return _commit;
  }

  void SigmaProof::SetCommit(QByteArray commit) 
  {
    _have_commit = true;
    _commit = commit;
  }

  Integer SigmaProof::GetChallenge() const
  {
    if(!_have_challenge) qFatal("Challenge not set");
    return _challenge;
  }

  void SigmaProof::SetChallenge(Integer challenge) 
  {
    _have_challenge = true;
    _challenge = challenge;
  }

  QByteArray SigmaProof::GetResponse() const
  {
    if(!_have_response) qFatal("Response not set");
    return _response;
  }

  void SigmaProof::SetResponse(QByteArray response) 
  {
    _have_response = true;
    _response = response;
  }


}
}
