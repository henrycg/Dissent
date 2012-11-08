#ifndef DISSENT_LRS_RING_SIGNATURE_H_GUARD
#define DISSENT_LRS_RING_SIGNATURE_H_GUARD

#include <QSharedPointer>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "SigmaProof.hpp"

namespace Dissent {
namespace LRS {

  class RingSignature {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      RingSignature(QByteArray context,
          QList<QSharedPointer<SigmaProof> > proofs, 
          int real_idx);

      /**
       * Destructor
       */
      virtual ~RingSignature();

      QByteArray Sign(const QByteArray msg);

      bool Verify(const QByteArray msg, const QByteArray sig);

    private:

      QByteArray CreateChallenge(const QByteArray &msg, const QList<QByteArray> &commits) const;
      QByteArray Xor(const QByteArray &a, const QByteArray &b) const;

      QByteArray _context;

      QList<QSharedPointer<SigmaProof> > _proofs;
      QList<SigmaProof::ProofType> _proof_types;
      int _real_idx;

      QList<QByteArray> _witness_images;
      QList<QByteArray> _linkage_tags;
  };

}
}

#endif
