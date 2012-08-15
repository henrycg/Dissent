#ifndef DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_SERVER_CIPHERTEXT_H_GUARD

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/Integer.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"
#include "PublicKeySet.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop server ciphertext
   */
  class ServerCiphertext {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize a ciphertext
       * @param params Group parameters
       * @param client_pks Client public keys
       */
      ServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> client_pks);

      /**
       * Constructor: Initialize a ciphertext from serialized version
       * @param params Group parameters
       * @param client_pks Client public keys
       * @param serialized serialized byte array
       */
      ServerCiphertext(const QSharedPointer<const Parameters> params, 
          const QSharedPointer<const PublicKeySet> client_pks,
          const QByteArray &serialized);

      /**
       * Destructor
       */
      virtual ~ServerCiphertext() {}

      /**
       * Initialize elements proving correctness of ciphertext
       * @param Server private key used to generate proof
       */
      void SetProof(const QSharedPointer<const PrivateKey> priv);

      /**
       * Check ciphertext proof
       * @param pub public key of server
       * @returns true if proof is okay
       */
      bool VerifyProof(const QSharedPointer<const PublicKey> pub) const;

      /**
       * Get serialized version
       */
      QByteArray GetByteArray() const;

      inline Element GetElement() const { return _element; }
      inline Integer GetChallenge() const { return _challenge; }
      inline Integer GetResponse() const { return _response; }

    private:

      Integer Commit(const Element &g1, const Element &g2, 
          const Element &y1, const Element &y2,
          const Element &t1, const Element &t2) const;

      QSharedPointer<const Parameters> _params;
      QSharedPointer<const PublicKeySet> _client_pks;

      Element _element;
      Integer _challenge;
      Integer _response;
  };
}
}
}

#endif
