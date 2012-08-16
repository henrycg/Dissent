#ifndef DISSENT_ANONYMITY_BLOG_DROP_ROUND_H_GUARD
#define DISSENT_ANONYMITY_BLOG_DROP_ROUND_H_GUARD

#include <QMetaEnum>

#include "Crypto/BlogDrop/BlogDropAuthor.hpp"
#include "Crypto/BlogDrop/BlogDropClient.hpp"
#include "Crypto/BlogDrop/BlogDropServer.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Crypto/BlogDrop/PrivateKey.hpp"
#include "Crypto/BlogDrop/PublicKey.hpp"
#include "Crypto/BlogDrop/PublicKeySet.hpp"
#include "RoundStateMachine.hpp"
#include "BaseBulkRound.hpp"
#include "NullRound.hpp"

namespace Dissent {
namespace Utils {
  class Random;
}

namespace Anonymity {
  class BlogDropRound : public BaseBulkRound
  {
    Q_OBJECT
    Q_ENUMS(States);
    Q_ENUMS(MessageType);

    public:
      friend class RoundStateMachine<BlogDropRound>;

      typedef Crypto::BlogDrop::BlogDropAuthor BlogDropAuthor;
      typedef Crypto::BlogDrop::BlogDropClient BlogDropClient;
      typedef Crypto::BlogDrop::BlogDropServer BlogDropServer;
      typedef Crypto::BlogDrop::Parameters Parameters;
      typedef Crypto::BlogDrop::PrivateKey PrivateKey;
      typedef Crypto::BlogDrop::PublicKey PublicKey;
      typedef Crypto::BlogDrop::PublicKeySet PublicKeySet;

      enum MessageType {
        CLIENT_CIPHERTEXT = 0,
        SERVER_PUBLIC_KEY,
        SERVER_CLIENT_LIST,
        SERVER_CLIENT_LIST_HASH,
        SERVER_CIPHERTEXT,
        SERVER_VALIDATION,
        SERVER_CLEARTEXT,
      };

      enum States {
        OFFLINE = 0,
        SHUFFLING,
        PROCESS_DATA_SHUFFLE,
        WAIT_FOR_SERVER_PUBLIC_KEYS,
        PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_CLIENT_LIST_HASHES,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT,
        FINISHED,
      };

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit BlogDropRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<NullRound>);

      /**
       * Destructor
       */
      virtual ~BlogDropRound();

      /**
       * Returns true if the local node is a member of the subgroup
       */
      inline bool IsServer() const
      {
        return GetGroup().GetSubgroup().Contains(GetLocalId());
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString StateToString(int state)
      {
        int index = staticMetaObject.indexOfEnumerator("States");
        return staticMetaObject.enumerator(index).valueToKey(state);
      }

      /**
       * Converts a MessageType into a QString
       * @param mt value to convert
       */
      static QString MessageTypeToString(int mtype)
      {
        int index = staticMetaObject.indexOfEnumerator("MessageType");
        return staticMetaObject.enumerator(index).valueToKey(mtype);
      }

      /**
       * Returns the string representation of the round
       */
      inline virtual QString ToString() const
      {
        return "BlogDropRound: " + GetRoundId().ToString() +
          " Phase: " + QString::number(_state_machine.GetPhase());
      }

      /**
       * Notifies this round that a peer has joined the session.  This will
       * cause this type of round to finished immediately.
       */
      virtual void PeerJoined() { _stop_next = true; }

      virtual void HandleDisconnect(const Id &id);

    protected:
      typedef Utils::Random Random;

      /**
       * Funnels data into the RoundStateMachine for evaluation
       * @param data Incoming data
       * @param from the remote peer sending the data
       */
      inline virtual void ProcessData(const Id &from, const QByteArray &data)
      {
        _state_machine.ProcessData(from, data);
      }

      /**
       * Called when the BulkRound is started
       */
      virtual void OnStart();

      /**
       * Called when the BulkRound is stopped
       */
      virtual void OnStop();

      /**
       * Server sends a message to all servers
       * @param data the message to send
       */
      void VerifiableBroadcastToServers(const QByteArray &data);

      /**
       * Server sends a message to all clients
       * @param data the message to send
       */
      void VerifiableBroadcastToClients(const QByteArray &data);

    private:
      /**
       * Holds the internal state for this round
       */
      class State {
        public:
          State() : 
            params(Parameters::IntegerProductionFixed()),
            anonymous_priv(new PrivateKey(params)),
            anonymous_pub(new PublicKey(anonymous_priv)) {}

          virtual ~State() {}

          /* My blogdrop keys */
          const QSharedPointer<const Parameters> params;
          const QSharedPointer<const PrivateKey> anonymous_priv;
          const QSharedPointer<const PublicKey> anonymous_pub;

          /* Set of all server PKs */
          QHash<int, QSharedPointer<const PublicKey> > server_pks;
          QSharedPointer<const PublicKeySet> server_pk_set;
          QList<QSharedPointer<const PublicKey> > slot_pks;

          /* Blogdrop ciphertext generators */
          QSharedPointer<BlogDropAuthor> blogdrop_author;
          QList<QSharedPointer<BlogDropClient> > blogdrop_clients;

          /* Plaintext output */
          QByteArray cleartext;

          QByteArray shuffle_data;

          QHash<int, QByteArray> signatures;

          int my_idx;
          int phase;
          Id my_server;

          int n_clients;
          int n_servers;
      };

      /**
       * Holds the internal state for servers in this round
       */
      class ServerState : public State {
        public:
          ServerState() :
            server_priv(new PrivateKey(params)),
            server_pub(new PublicKey(server_priv)) {}

          virtual ~ServerState() {}

          int expected_clients;
          QSet<Id> allowed_clients;

          /* Blogdrop server keys */
          QSharedPointer<PrivateKey> server_priv;
          QSharedPointer<PublicKey> server_pub;

          /* Blogdrop server bins */
          QList<QSharedPointer<BlogDropServer> > blogdrop_servers;

          /* Serialized hash[id] = serialized list of serialized ciphertexts */
          QHash<Id,QByteArray> client_ciphertexts;

          QByteArray my_client_list_hash;
          QByteArray my_ciphertext;

          QSet<Id> handled_servers;
          QHash<int, QByteArray> server_ciphertexts;
      };

      /**
       * Called by the constructor to initialize the server state machine
       */
      void InitServer();

      /**
       * Called by the constructor to initialize the client state machine
       */
      void InitClient();

      /**
       * Called before each state transition
       */
      void BeforeStateTransition();

      /**
       * Called after each cycle, i.e., phase conclusion
       */
      bool CycleComplete();

      /**
       * Safety net, should never be called
       */
      void EmptyHandleMessage(const Id &, QDataStream &)
      {
        qDebug() << "Received a message into the empty handle message...";
      }
        
      /**
       * Some transitions don't require any state preparation, they are handled
       * by this
       */
      void EmptyTransitionCallback() {}

      /**
       * Submits the anonymous signing key into the shuffle
       */
      virtual QPair<QByteArray, bool> GetShuffleData(int max);

      /**
       * Called when the shuffle finishes
       */
      virtual void ShuffleFinished();

      /**
       * Client handles public key from server
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerPublicKey(const Id &from, QDataStream &stream);

      /**
       * Server handles client ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleClientCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server client list messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientList(const Id &from, QDataStream &stream);

      /**
       * Server handles other server hash messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerClientListHash(const Id &from, QDataStream &stream);

      /**
       * Server handles other server ciphertext messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCiphertext(const Id &from, QDataStream &stream);

      /**
       * Server handles other server validation messages
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerValidation(const Id &from, QDataStream &stream);

      /**
       * Client handles server cleartext message
       * @param from sender of the message
       * @param stream message
       */
      void HandleServerCleartext(const Id &from, QDataStream &stream);

      /* Below are the state transitions */
      void StartShuffle();
      void ProcessDataShuffle();
      void ProcessKeyShuffle();
      void SubmitServerPublicKey();
      void PrepareForBulk();
      void SubmitClientCiphertext();
      void SetOnlineClients();
      void SubmitClientList();
      void SubmitServerClientListHash();
      void SubmitServerCiphertext();
      void GenerateServerCiphertext();
      QByteArray GenerateClientCiphertext();
      void SubmitValidation();
      void PushCleartext();

      void ProcessCleartext();
      void ConcludeClientCiphertextSubmission(const int &);

      QSharedPointer<ServerState> _server_state;
      QSharedPointer<State> _state;
      RoundStateMachine<BlogDropRound> _state_machine;
      bool _stop_next;
  };
}
}

#endif
