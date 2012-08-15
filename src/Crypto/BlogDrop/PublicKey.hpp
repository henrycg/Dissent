#ifndef DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_H_GUARD

#include "Crypto/AbstractGroup/Element.hpp"
#include "Parameters.hpp"
#include "PrivateKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding BlogDrop public key (g^sk)
   */
  class PublicKey {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Initialize and empty public key
       */
      PublicKey();

      /**
       * Constructor: Initialize a public key matching a private key
       * @param key the key to use
       */
      PublicKey(const QSharedPointer<const PrivateKey> key);
      PublicKey(const PrivateKey &key);

      /**
       * Initialize an empty public key with these parameters
       * @params params group parameters
       * @params key serialized key
       */
      PublicKey(const QSharedPointer<const Parameters> params, const QByteArray &key);

      /**
       * Initialize a public key with this value
       * @params params group parameters
       * @params key integer key value
       */
      PublicKey(const QSharedPointer<const Parameters> params, const Element key);

      /**
       * Destructor
       */
      virtual ~PublicKey() {}

      /**
       * Get the parameters for this public key 
       */
      const QSharedPointer<const Parameters> GetParameters() const { return _params; }

      /**
       * Get element representing the key
       */
      Element GetElement() const { return _public_key; }

      /**
       * Sets key to specified integer
       * @param e element to set
       */
      void SetElement(Element e) { _public_key = e; }

      /**
       * Get serialized version of the integer
       */
      inline QByteArray GetByteArray() const { return _public_key.GetByteArray(); }

      /**
       * Is the key valid?
       */
      inline bool IsValid() const { return _params->GetGroup()->IsElement(_public_key); }

      /**
       * Equality operator
       * @param other integer to compare
       */
      inline bool operator==(const PublicKey &other) const
      {
        return (_public_key == other.GetElement());
      }

    private:

      QSharedPointer<const Parameters> _params;
      Element _public_key;

  };

  inline uint qHash(const PublicKey &key) { 
    return qHash(key.GetElement().GetByteArray());
  }
}
}
}

#endif
