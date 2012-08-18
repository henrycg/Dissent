#ifndef DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_SET_H_GUARD
#define DISSENT_CRYPTO_BLOGDROP_PUBLICKEY_SET_H_GUARD

#include <QList>
#include <QSharedPointer>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Parameters.hpp"
#include "PublicKey.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  /**
   * Object holding a collection of public keys. 
   * This object does some preprocessing on the keys to 
   * speed up ciphertext operations.
   */
  class PublicKeySet {

    public:

      typedef Dissent::Crypto::AbstractGroup::Element Element;

      /**
       * Constructor: Initialize using a QSet of keys
       * @params params group parameters
       * @params keys keyset to use
       */
      PublicKeySet(const QSharedPointer<const Parameters> params, 
          const QList<QSharedPointer<const PublicKey> > &keys);

      /**
       * Return a list of PublicKeySets -- one per ciphertext element.
       * @params params group parameters
       * @params keys a list of format keys[client][element. You will probably
       *         generate this by calling client_ciphertext->GetOneTimeKeys()
       *         many times.
       */
      static QList<QSharedPointer<const PublicKeySet> > CreateClientKeySets(
          const QSharedPointer<const Parameters> params, 
          const QList<QList<QSharedPointer<const PublicKey> > > &keys);


      /**
       * Destructor
       */
      virtual ~PublicKeySet() {}

      /**
       * Get element representing the keyset
       */
      const Element GetElement() const { return _key; }

    private:

      const QSharedPointer<const Parameters> _params;

      /**
       * Product of all public keys:
       *   key = (g^x0)(g^x1)...(g^xN)
       */
      Element _key;
  };
}
}
}

#endif
