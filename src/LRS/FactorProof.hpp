#ifndef DISSENT_LRS_FACTOR_PROOF_H_GUARD
#define DISSENT_LRS_FACTOR_PROOF_H_GUARD

#include <QSslKey>

#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"

#include "SigmaProof.hpp"

namespace Dissent {
namespace LRS {

  /**
   * Proof of knowledge derived from:
   * Camenisch and Stadler - CRYPTO 1997
   */
  class FactorProof : public SigmaProof {

    public:

      static const int RsaEncryptionExponent = 3;

      typedef Dissent::Crypto::AbstractGroup::Element Element;
      typedef Dissent::Crypto::AbstractGroup::AbstractGroup AbstractGroup;

      /**
       * Constructor
       */
      FactorProof(QByteArray context, int n_bits);

      FactorProof(QByteArray context, QSslKey public_key);

      FactorProof(QByteArray context, 
          QByteArray witness, 
          QByteArray witness_image);

      FactorProof(QByteArray context,
          QByteArray witness_image,
          QByteArray linkage_tag,
          QByteArray commit, 
          QByteArray challenge, 
          QByteArray response);

      /**
       * Destructor
       */
      virtual ~FactorProof();

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

      QByteArray WitnessImageBytes() const;
      QByteArray CommitBytes() const;
      void PrintDebug() const;
      Integer CommitHash() const;

      QSharedPointer<AbstractGroup> _group;

      QByteArray _context;

      Integer _witness; // witness == the eth root of h = Hash(stuff)
      Element _witness_image; // witness_image == g^h

      Element _tag_generator;
      Element _linkage_tag;

      Element _commit_1;
      Element _commit_2;
      Integer _commit_secret;

      Integer _challenge;
      Integer _response;

      Element _g1; // g^m
      Element _g2; // g^mm or random (for fake proof)
      Element _g3; // g^mmm
  };

}
}

#endif
