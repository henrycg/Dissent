#ifndef DISSENT_LRS_SIGMA_PROOF_H_GUARD
#define DISSENT_LRS_SIGMA_PROOF_H_GUARD

#include <QVariant>

#include "Crypto/Integer.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::Integer Integer;

  class SigmaProof {

    public:

      typedef enum {
        ProofType_FactorProof,
        ProofType_SchnorrProof
      } ProofType;

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
      SigmaProof(ProofType type); 

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
       * Create a (commit, challenge, response) tuple
       * that is valid
       */
      virtual void FakeProve() = 0;

      /**
       * Verify the (commit, challenge, response) tuple
       * @param verify_challenge check that the challenge is
       *        a hash of the proof parameters and the commitment.
       *        This should be "true" to verify a signle non-interactive
       *        proof, but should be "false" when the proof is used
       *        as part of a larger ring signature scheme.
       */
      virtual bool Verify(bool verify_challenge = true) const = 0;

      /**
       * Get the witness for this proof of knowledge.
       * For example, if this is a proof of knowledge of discrete
       * log, return x
       */
      QByteArray GetWitness() const;

      /**
       * Get the image of the witness for this proof of knowledge.
       * For example, if this is a proof of knowledge of discrete
       * log, return g^x
       */
      QByteArray GetWitnessImage() const;

      /**
       * Get the linkage tag associated with this witness.
       * For example, if we're using discrete log, return h^x
       */
      QByteArray GetLinkageTag() const;

      /**
       * Get a serialized representation of the commit
       * for this Sigma proof
       */
      QByteArray GetCommit() const;

      /**
       * Get the challenge integer for this proof
       */
      Integer GetChallenge() const;

      /**
       * Get a serialized representation of the response
       * for this Sigma proof
       */
      QByteArray GetResponse() const;

      /**
       * Get type of proof
       */
      inline ProofType GetProofType() const { return _type; }

    protected:

      void SetWitness(QByteArray witness);
      void SetWitnessImage(QByteArray witness_image);
      void SetLinkageTag(QByteArray linkage_tag);
      void SetCommit(QByteArray commit);
      void SetChallenge(Integer challenge);
      void SetResponse(QByteArray response);

      QVariant IntegerToVariant(Integer i) const;
      
      Integer VariantToInteger(QVariant v) const;

    private:

      ProofType _type;

      bool _have_witness;
      QByteArray _witness;

      bool _have_witness_image;
      QByteArray _witness_image;

      bool _have_linkage_tag;
      QByteArray _linkage_tag;

      bool _have_commit;
      QByteArray _commit;

      bool _have_challenge;
      Integer _challenge;

      bool _have_response;
      QByteArray _response;
  };

}
}

#endif
