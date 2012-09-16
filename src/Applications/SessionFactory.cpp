#include "Anonymity/BaseBulkRound.hpp"
#include "Anonymity/BlogDropRound.hpp"
#include "Anonymity/BulkRound.hpp"
#include "Anonymity/CSBulkRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/NeffKeyShuffle.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionLeader.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/NullAuthenticator.hpp"
#include "Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"
#include "Node.hpp"

using Dissent::Anonymity::BulkRound;
using Dissent::Anonymity::BlogDropRound;
using Dissent::Anonymity::CSBulkRound;
using Dissent::Anonymity::NeffKeyShuffle;
using Dissent::Anonymity::NullRound;
using Dissent::Anonymity::RepeatingBulkRound;
using Dissent::Anonymity::Sessions::Session;
using Dissent::Anonymity::Sessions::SessionLeader;
using Dissent::Anonymity::ShuffleRound;
using Dissent::Anonymity::TCreateBlogDropRound_ElGamal;
using Dissent::Anonymity::TCreateBlogDropRound_Hashing;
using Dissent::Anonymity::TCreateBlogDropRound_Pairing;
using Dissent::Anonymity::TCreateBulkRound;
using Dissent::Anonymity::TCreateRound;
using Dissent::Connections::ConnectionManager;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Network;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::BlogDrop::Parameters;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Identity::Group;
using Dissent::Identity::Authentication::IAuthenticate;
using Dissent::Identity::Authentication::IAuthenticator;
using Dissent::Identity::Authentication::NullAuthenticate;
using Dissent::Identity::Authentication::NullAuthenticator;
using Dissent::Messaging::RpcHandler;

namespace Dissent {
namespace Applications {

  void SessionFactory::CreateSession(Node *node, const Id &session_id,
      SessionType type, AuthFactory::AuthType auth_type,
      const QSharedPointer<KeyShare> &public_keys)
  {
    CreateRound cr;
    switch(type) {
      case NULL_ROUND:
        cr = &TCreateRound<NullRound>;
        break;
      case SHUFFLE:
        cr = &TCreateRound<ShuffleRound>;
        break;
      case BULK:
        cr = &TCreateRound<BulkRound>;
        break;
      case REPEATING_BULK:
        cr = &TCreateRound<RepeatingBulkRound>;
        break;
      case CSBULK:
        cr = &TCreateBulkRound<CSBulkRound, NeffKeyShuffle>;
        break;
      case BLOGDROP_PAIRING:
        cr = &TCreateBlogDropRound_Pairing<BlogDropRound>;
        break;
      case BLOGDROP_ELGAMAL:
        cr = &TCreateBlogDropRound_ElGamal<BlogDropRound>;
        break;
      case BLOGDROP_HASHING:
        cr = &TCreateBlogDropRound_Hashing<BlogDropRound>;
        break;
      default:
        qFatal("Invalid session type");
    }

    QSharedPointer<IAuthenticate> authe(AuthFactory::CreateAuthenticate(
          node, auth_type, public_keys));

    Session *session = new Session(node->GetGroupHolder(), authe, session_id,
        node->GetNetwork(), cr);

    QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnecting()),
        session, SLOT(CallStop()));

    QSharedPointer<Session> psession(session);
    session->SetSharedPointer(psession);
    node->GetSessionManager().AddSession(psession);

    psession->SetSink(node->GetSink().data());
    if(node->GetPrivateIdentity().GetLocalId() ==
        node->GetGroupHolder()->GetGroup().GetLeader())
    {
      QSharedPointer<IAuthenticator> autho(AuthFactory::CreateAuthenticator(
            node, auth_type, public_keys));
      QSharedPointer<SessionLeader> sl(new SessionLeader(
            node->GetGroupHolder()->GetGroup(), node->GetPrivateIdentity(),
            node->GetNetwork(), psession, autho));
      node->GetSessionManager().AddSessionLeader(sl);
      sl->Start();
    } else {
      psession->Start();
    }
  }
}
}
