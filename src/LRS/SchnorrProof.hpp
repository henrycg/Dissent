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
      SchnorrProof(QByteArray context);

      SchnorrProof(QByteArray context,
          QByteArray witness, 
          QByteArray witness_image);

      SchnorrProof(QByteArray context,
          QByteArray witness_image,
          QByteArray linkage_tag, 
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

    private:
      QByteArray CommitBytes(Element commit_1, Element commit_2) const; 
      Integer CommitHash() const;

      QSharedPointer<AbstractGroup> _group;

      QByteArray _context;

      Integer _witness;
      Element _witness_image;

      Element _tag_generator;
      Element _linkage_tag;

      Element _commit_1;
      Element _commit_2;
      Integer _commit_secret;

      Integer _challenge;
      Integer _response;

  };

}
}

#endif
