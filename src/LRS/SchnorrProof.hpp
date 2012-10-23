#ifndef DISSENT_LRS_SCHNORR_PROOF_H_GUARD
#define DISSENT_LRS_SCHNORR_PROOF_H_GUARD

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "SigmaProof.hpp"

namespace Dissent {
namespace LRS {

  typedef Dissent::Crypto::AbstractGroup::Element Element;

  class SchnorrProof : public SigmaProof {

    public:

      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      SchnorrProof(QSharedPointer<AbstractGroup> g);

      SchnorrProof(QSharedPointer<AbstractGroup> g, 
          QByteArray witness, 
          QByteArray witness_image);

      SchnorrProof(QSharedPointer<AbstractGroup> g, 
          QByteArray witness_image,
          QByteArray commit, 
          QByteArray challenge, 
          QByteArray response);

      /**
       * Destructor
       */
      virtual ~SchnorrProof();

      /**
       * Generate the commitment for the start of
       * a Sigma protocol
       */
      virtual void GenerateCommit();

      /**
       * Generate a random challenge for a Sigma
       * protocol
       */
      virtual void GenerateChallenge();

      /**
       * Prove using a random challenge
       */
      virtual void Prove();

      /** 
       * Prove using the specified challenge.
       * Should pad the challenge with random bits 
       * up to the maximum length.
       */
      virtual void Prove(QByteArray challenge);

      /**
       * Prove using the specified integer as a challenge.
       * The integer value is used _unmodified_, unlike
       * the above version of Prove().
       */
      virtual void Prove(Integer challenge);

      /**
       * Create a (commit, challenge, response) tuple
       * that is valid
       */
      virtual void FakeProve();

      /**
       * Verify the (commit, challenge, response) tuple
       * @param verify_challenge check that the challenge is
       *        a hash of the proof parameters and the commitment.
       *        This should be "true" to verify a signle non-interactive
       *        proof, but should be "false" when the proof is used
       *        as part of a larger ring signature scheme.
       */
      virtual bool Verify(bool verify_challenge=true) const;

      /**
       * Set the witness
       */
      inline void SetWitness(Integer w) { _witness = w; }

      /**
       * Get the image of the witness for this proof of knowledge.
       * For example, if this is a proof of knowledge of discrete
       * log, return g^x
       */
      virtual QByteArray GetWitnessImage() const { return _group->ElementToByteArray(_witness_image); }

      /**
       * Get a serialized representation of the commit
       * for this Sigma proof
       */
      virtual QByteArray GetCommit() const { return _group->ElementToByteArray(_commit); }

      /**
       * Get the challenge integer for this proof
       */
      virtual inline Integer GetChallenge() const { return _challenge; }

      /**
       * Get a serialized representation of the response
       * for this Sigma proof
       */
      virtual QByteArray GetResponse() const { return _response.GetByteArray(); }

    private:

      Integer CommitHash() const;

      QSharedPointer<AbstractGroup> _group;

      Integer _witness;
      Element _witness_image;
      Element _commit;
      Integer _commit_secret;
      Integer _challenge;
      Integer _response;

  };

}
}

#endif
