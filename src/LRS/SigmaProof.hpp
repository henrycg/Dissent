#ifndef DISSENT_LRS_SIGMA_PROOF_H_GUARD
#define DISSENT_LRS_SIGMA_PROOF_H_GUARD

#include <QVariant>

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::Integer Integer;

  class SigmaProof {

    public:

      /**
       * Constructor
       *
       * The default constructor should
       * generate a random witness and witness
       * image for the relation represented by this
       * Sigma protocol. For example, if we're using
       * proof-of-knowledge for discrete log,
       * generate a pair (x, g^x) for a random x.
       */
      SigmaProof() {}

      /**
       * Destructor
       */
      virtual ~SigmaProof() {}

      /**
       * Generate the commitment for the start of
       * a Sigma protocol
       */
      virtual void GenerateCommit() = 0;

      /**
       * Generate a random challenge for a Sigma
       * protocol
       */
      virtual void GenerateChallenge() = 0;

      /**
       * Prove using a random challenge
       */
      virtual void Prove() = 0;

      /** 
       * Prove using the specified challenge.
       * Should pad the challenge with random bits 
       * up to the maximum length.
       */
      virtual void Prove(QByteArray challenge) = 0;

      /**
       * Prove using the specified integer as a challenge.
       * The integer value is used _unmodified_, unlike
       * the above version of Prove().
       */
      virtual void Prove(Integer challenge) = 0;

      /**
       * Create a (commit, challenge, response) tuple
       * that is valid
       */
      virtual void FakeProve() = 0;

      /**
       * Verify the (commit, challenge, response) tuple
       */
      virtual bool Verify(bool verify_challenge = true) const = 0;

      /**
       * Get the image of the witness for this proof of knowledge.
       * For example, if this is a proof of knowledge of discrete
       * log, return g^x
       */
      virtual QByteArray GetWitnessImage() const = 0;

      /**
       * Get a serialized representation of the commit
       * for this Sigma proof
       */
      virtual QByteArray GetCommit() const = 0;

      /**
       * Get the challenge integer for this proof
       */
      virtual Integer GetChallenge() const = 0;

      /**
       * Get a serialized representation of the response
       * for this Sigma proof
       */
      virtual QByteArray GetResponse() const = 0;

    protected:

      QVariant IntegerToVariant(Integer i) const;
      
      Integer VariantToInteger(QVariant v) const;

    private:

  };

}
}

#endif
