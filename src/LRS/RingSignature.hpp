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
       * @param proofs SigmaProofs to use for signature
       * @param real_idx index of proof for which the signer knows
       *                 the witness
       */
      RingSignature(QByteArray context,
          QList<QSharedPointer<SigmaProof> > proofs, 
          int real_idx);

      /**
       * Destructor
       */
      virtual ~RingSignature();

      /**
       * Sign the message using the ring signature scheme
       * @param msg message to be signed
       */
      QByteArray Sign(const QByteArray msg);

      /**
       * Verify a ring signature
       * @param msg message 
       * @param sig signature
       */
      bool Verify(const QByteArray msg, const QByteArray sig);

    private:

      QByteArray CreateChallenge(const QByteArray &msg, const QList<QByteArray> &commits) const;
      QByteArray Xor(const QByteArray &a, const QByteArray &b) const;

      QByteArray _context;

      QList<QSharedPointer<SigmaProof> > _proofs;
      QList<SigmaProof::ProofType> _proof_types;
      int _real_idx;

      QList<QByteArray> _witness_images;
  };

}
}

#endif
