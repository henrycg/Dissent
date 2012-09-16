#include <QtConcurrentRun>

#include "Crypto/Hash.hpp"
#include "Crypto/BlogDrop/BlogDropUtils.hpp"
#include "Crypto/BlogDrop/ClientCiphertext.hpp"
#include "Crypto/BlogDrop/ServerCiphertext.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Utils/Random.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/Time.hpp"
#include "Utils/Utils.hpp"

#include "BlogDropRound.hpp"

namespace Dissent {
  using Crypto::BlogDrop::ClientCiphertext;
  using Crypto::BlogDrop::BlogDropUtils;
  using Crypto::BlogDrop::Plaintext;
  using Crypto::BlogDrop::ServerCiphertext;
  using Crypto::CryptoFactory;
  using Crypto::Hash;
  using Crypto::Library;
  using Identity::PublicIdentity;
  using Utils::QRunTimeError;
  using Utils::Serialization;

namespace Anonymity {

  BlogDropRound::BlogDropRound(QSharedPointer<Parameters> params,
      const Group &group, const PrivateIdentity &ident,
      const Id &round_id, QSharedPointer<Network> network,
      GetDataCallback &get_data, CreateRound create_shuffle) :
    BaseBulkRound(group, ident, round_id, network, get_data, create_shuffle),
    _params(params),
    _state_machine(this),
    _stop_next(false)
  {
    _state_machine.AddState(OFFLINE);
    _state_machine.AddState(SHUFFLING, -1, 0, &BlogDropRound::StartShuffle);
    _state_machine.AddState(FINISHED);
    _state_machine.AddState(PREPARE_FOR_BULK, -1, 0,
        &BlogDropRound::PrepareForBulk);
    _state_machine.AddState(PROCESS_DATA_SHUFFLE, -1, 0,
        &BlogDropRound::ProcessDataShuffle);

    _state_machine.AddTransition(SHUFFLING, PROCESS_DATA_SHUFFLE);

    _state_machine.AddTransition(OFFLINE, SHUFFLING);
    _state_machine.SetState(OFFLINE);

    if(group.GetSubgroup().Contains(ident.GetLocalId())) {
      InitServer();
    } else {
      InitClient();
    }

    _state->n_servers = GetGroup().GetSubgroup().Count();
    _state->n_clients = GetGroup().Count();

    // All slots start out closed
    _state->slots_open = QBitArray(GetGroup().Count(), false);
  }

  void BlogDropRound::InitServer()
  {
    _params->SetRoundNonce(GetRoundId().GetByteArray());
    _server_state = QSharedPointer<ServerState>(new ServerState(_params));
    _state = _server_state;
    Q_ASSERT(_state);

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      _server_state->allowed_clients.insert(con->GetRemoteId());
    }

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_PUBLIC_KEYS,
        CLIENT_PUBLIC_KEY, &BlogDropRound::HandleClientPublicKey,
        &BlogDropRound::SubmitClientPublicKey);

    _state_machine.AddState(WAIT_FOR_SERVER_PUBLIC_KEYS,
        SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey, 
        &BlogDropRound::SubmitServerPublicKey);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        CLIENT_CIPHERTEXT, &BlogDropRound::HandleClientCiphertext,
        &BlogDropRound::SetOnlineClients);

    _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_CLIENT_LIST, &BlogDropRound::HandleServerClientList,
        &BlogDropRound::SubmitClientList);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_CIPHERTEXT, &BlogDropRound::HandleServerCiphertext,
        &BlogDropRound::SubmitServerCiphertext);

    _state_machine.AddState(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_VALIDATION, &BlogDropRound::HandleServerValidation,
        &BlogDropRound::SubmitValidation);

    _state_machine.AddState(SERVER_PUSH_CLEARTEXT, -1, 0,
        &BlogDropRound::PushCleartext);

    _state_machine.AddTransition(PROCESS_DATA_SHUFFLE, 
        SERVER_WAIT_FOR_CLIENT_PUBLIC_KEYS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_PUBLIC_KEYS, 
        WAIT_FOR_SERVER_PUBLIC_KEYS);

    if(UsesHashingGenerator()) {
      _state_machine.AddState(SERVER_WAIT_FOR_CLIENT_MASTER_PUBLIC_KEYS,
          CLIENT_MASTER_PUBLIC_KEY, &BlogDropRound::HandleClientMasterPublicKey,
          &BlogDropRound::SubmitClientMasterPublicKey);

      _state_machine.AddState(WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS,
          SERVER_MASTER_PUBLIC_KEY, &BlogDropRound::HandleServerMasterPublicKey, 
          &BlogDropRound::SubmitServerMasterPublicKey);

      _state_machine.AddTransition(WAIT_FOR_SERVER_PUBLIC_KEYS,
          SERVER_WAIT_FOR_CLIENT_MASTER_PUBLIC_KEYS);
      _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_MASTER_PUBLIC_KEYS,
          WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS);
      _state_machine.AddTransition(WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS,
          PREPARE_FOR_BULK);
    } else {
      _state_machine.AddTransition(WAIT_FOR_SERVER_PUBLIC_KEYS, 
          PREPARE_FOR_BULK);
    }

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_CIPHERTEXT,
        SERVER_WAIT_FOR_CLIENT_LISTS);
    _state_machine.AddTransition(SERVER_WAIT_FOR_CLIENT_LISTS,
        SERVER_WAIT_FOR_SERVER_CIPHERTEXT);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_CIPHERTEXT,
        SERVER_WAIT_FOR_SERVER_VALIDATION);
    _state_machine.AddTransition(SERVER_WAIT_FOR_SERVER_VALIDATION,
        SERVER_PUSH_CLEARTEXT);
    _state_machine.AddTransition(SERVER_PUSH_CLEARTEXT,
        SERVER_WAIT_FOR_CLIENT_CIPHERTEXT);

    _state_machine.SetCycleState(SERVER_PUSH_CLEARTEXT);
  }

  void BlogDropRound::InitClient()
  {
    _params->SetRoundNonce(GetRoundId().GetByteArray());
    _state = QSharedPointer<State>(new State(_params));

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(GetGroup().GetSubgroup().Contains(con->GetRemoteId())) {
        _state->my_server = con->GetRemoteId();
        break;
      }
    }

    _state_machine.AddState(WAIT_FOR_SERVER_PUBLIC_KEYS,
        SERVER_PUBLIC_KEY, &BlogDropRound::HandleServerPublicKey, 
        &BlogDropRound::SubmitClientPublicKey);
    
    _state_machine.AddState(WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS,
        SERVER_MASTER_PUBLIC_KEY, &BlogDropRound::HandleServerMasterPublicKey,
        &BlogDropRound::SubmitClientMasterPublicKey);

    _state_machine.AddState(CLIENT_WAIT_FOR_CLEARTEXT,
        SERVER_CLEARTEXT, &BlogDropRound::HandleServerCleartext,
        &BlogDropRound::SubmitClientCiphertext);

    _state_machine.AddTransition(PROCESS_DATA_SHUFFLE, 
        WAIT_FOR_SERVER_PUBLIC_KEYS);

    if(UsesHashingGenerator()) {
      _state_machine.AddTransition(WAIT_FOR_SERVER_PUBLIC_KEYS,
          WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS);
      _state_machine.AddTransition(WAIT_FOR_SERVER_MASTER_PUBLIC_KEYS, 
          PREPARE_FOR_BULK);
    } else {
      _state_machine.AddTransition(WAIT_FOR_SERVER_PUBLIC_KEYS, 
          PREPARE_FOR_BULK);
    }

    _state_machine.AddTransition(PREPARE_FOR_BULK,
        CLIENT_WAIT_FOR_CLEARTEXT);
    _state_machine.AddTransition(CLIENT_WAIT_FOR_CLEARTEXT,
        CLIENT_WAIT_FOR_CLEARTEXT);

    _state_machine.SetCycleState(CLIENT_WAIT_FOR_CLEARTEXT);
  }

  BlogDropRound::~BlogDropRound()
  {
  }

  void BlogDropRound::VerifiableBroadcastToServers(const QByteArray &data)
  {
    Q_ASSERT(IsServer());

    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const PublicIdentity &pi, GetGroup().GetSubgroup()) {
      GetNetwork()->Send(pi.GetId(), msg);
    }
  }

  void BlogDropRound::VerifiableBroadcastToClients(const QByteArray &data)
  {
    Q_ASSERT(IsServer());

    QByteArray msg = data + GetSigningKey()->Sign(data);
    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      GetNetwork()->Send(con->GetRemoteId(), msg);
    }
  }

  void BlogDropRound::OnStart()
  {
    Round::OnStart();
    _state_machine.StateComplete();
  }

  void BlogDropRound::OnStop()
  {
    _state_machine.SetState(FINISHED);
    Utils::PrintResourceUsage(ToString() + " " + "finished bulk");
    Round::OnStop();
  }

  void BlogDropRound::HandleDisconnect(const Id &id)
  {
    if(!GetGroup().Contains(id)) {
      return;
    } else {
      SetInterrupted();
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void BlogDropRound::BeforeStateTransition()
  {
    if(_server_state) {
      _server_state->handled_servers.clear();
    }
  }

  bool BlogDropRound::CycleComplete()
  {
    if(_server_state) {
      _server_state->client_ciphertexts.clear();
      _server_state->server_ciphertexts.clear();

      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        _server_state->blogdrop_servers[slot_idx]->ClearBin();
        _server_state->blogdrop_servers[slot_idx]->NextPhase();
        //qDebug() << "Server slot" << slot_idx << "phase" << _server_state->blogdrop_servers[slot_idx]->GetPhase();
      }
    }

    // Increment the always_open pointer until we find a closed
    // slot or we wrap around
    for(int user_idx=0; user_idx<_state->n_clients; user_idx++) {
      _state->always_open = (_state->always_open+1) % _state->n_clients;
      if(!_state->slots_open[_state->always_open]) break;
    }

    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      _state->blogdrop_clients[slot_idx]->NextPhase();
      //qDebug() << "Client slot" << slot_idx << "phase" << _state->blogdrop_clients[slot_idx]->GetPhase();
    }

    _state->blogdrop_author->NextPhase();

    if(_stop_next) {
      SetInterrupted();
      Stop("Stopped for join");
      return false;
    }
    return true;
  }

  void BlogDropRound::HandleClientPublicKey(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if((from != GetLocalId()) && !_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a public key");
    } else if(_server_state->client_pub_packets.contains(from)) {
      throw QRunTimeError("Already have public key");
    }

    QPair<QByteArray, QByteArray> pair;
    stream >> pair;

    _server_state->client_pub_packets[from] = pair;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client public key from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_pub_packets.count()
      << "expecting" << _server_state->allowed_clients.count();

    // Allowed clients + 1 (server submits key to self)
    if((_server_state->allowed_clients.count() + 1) ==
        _server_state->client_pub_packets.count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleClientMasterPublicKey(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if((from != GetLocalId()) && !_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a public key");
    } else if(_server_state->client_master_pub_packets.contains(from)) {
      throw QRunTimeError("Already have public key");
    }

    QPair<QByteArray, QByteArray> pair;
    stream >> pair;

    _server_state->client_master_pub_packets[from] = pair;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client master public key from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_master_pub_packets.count()
      << "expecting" << _server_state->allowed_clients.count();

    // Allowed clients + 1 (server submits key to self)
    if((_server_state->allowed_clients.count() + 1) ==
        _server_state->client_master_pub_packets.count())
    {
      _state_machine.StateComplete();
    } 
  }


  void BlogDropRound::HandleServerPublicKey(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Got public key from non-server");
    }

    const int server_idx = GetGroup().GetSubgroup().GetIndex(from);

    if(_state->server_pks.contains(server_idx)) {
      throw QRunTimeError("Already have server public key");
    }

    QByteArray public_key;
    QByteArray proof;
    QHash<Id, QPair<QByteArray, QByteArray> > client_pub_packets;
    stream >> public_key >> proof >> client_pub_packets;

    _state->server_pks[server_idx] = QSharedPointer<const PublicKey>(
        new PublicKey(_state->params, public_key));

    if(!_state->server_pks[server_idx]->IsValid()) {
      Stop("Got invalid public key--aborting");
      return;
    }

    if(!_state->server_pks[server_idx]->VerifyKnowledge(proof)) {
      Stop("Server failed to prove knowledge of secret key--aborting");
      return;
    }

    const QList<Id> keys = client_pub_packets.keys();
    for(int idx=0; idx<keys.count(); idx++) {
      const Id &client_id = keys[idx];

      QPair<QByteArray, QByteArray> pair = client_pub_packets[client_id];
      if(!GetGroup().GetKey(client_id)->Verify(pair.first, pair.second)) {
        Stop("Got public key with invalid signature");
        return;
      }

      Id round_id;
      QByteArray key_bytes, proof_bytes;
      QDataStream stream(pair.first);
      stream >> round_id >> proof_bytes >> key_bytes;

      if(round_id != GetRoundId()) {
        Stop("Got public key with invalid round ID");
        return;
      }

      _state->client_pks[client_id] = QSharedPointer<const PublicKey>(new PublicKey(_state->params, key_bytes));
      if(!_state->client_pks[client_id]->IsValid()) {
        Stop("Got invalid client public key");
        return;
      }

      if(!_state->client_pks[client_id]->VerifyKnowledge(proof_bytes)) {
        Stop("Got invalid client public key proof of knowledge");
        return;
      }
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received server public key from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _state->server_pks.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->server_pks.count() == GetGroup().GetSubgroup().Count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleServerMasterPublicKey(const Id &from, QDataStream &stream)
  {
    if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Got public key from non-server");
    }

    const int server_idx = GetGroup().GetSubgroup().GetIndex(from);

    if(_state->master_server_pks.contains(server_idx)) {
      throw QRunTimeError("Already have server public key");
    }

    QByteArray public_key;
    QList<QByteArray> commits;
    QHash<Id, QPair<QByteArray, QByteArray> > client_master_pub_packets;
    stream >> public_key >> commits >> client_master_pub_packets;

    QList<QSharedPointer<const PublicKey> > server_keys;
    for(int i=0; i<commits.count(); i++) {
      server_keys.append(QSharedPointer<const PublicKey>(new PublicKey(_state->params, commits[i])));
    }

    /* matrix[server_idx][client_idx] = commit */
    _state->commit_matrix_servers[server_idx] = server_keys;

    if(commits.count() != GetGroup().Count()) {
      Stop("Got invalid server commits");
      return;
    }

    const QList<Id> keys = client_master_pub_packets.keys();
    for(int idx=0; idx<keys.count(); idx++) {
      const Id &client_id = keys[idx];

      QPair<QByteArray, QByteArray> pair = client_master_pub_packets[client_id];
      if(!GetGroup().GetKey(client_id)->Verify(pair.first, pair.second)) {
        Stop("Got public key with invalid signature");
        return;
      }

      Id round_id;
      QList<QByteArray> client_commits;
      QDataStream stream(pair.first);
      stream >> round_id >> client_commits;

      if(round_id != GetRoundId()) {
        Stop("Got public key with invalid round ID");
        return;
      }

      if(client_commits.count() != GetGroup().GetSubgroup().Count()) {
        Stop("Got invalid client commits");
        return;
      }

      QList<QSharedPointer<const PublicKey> > keys;
      for(int i=0; i<client_commits.count(); i++) {
        keys.append(QSharedPointer<const PublicKey>(
              new PublicKey(_state->params, client_commits[i])));
      }

      _state->commit_matrix_clients[GetGroup().GetIndex(client_id)] = keys;
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received server master public key from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _state->commit_matrix_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_state->commit_matrix_servers.count() == GetGroup().GetSubgroup().Count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleServerCleartext(const Id &from, QDataStream &stream)
  {
    if(IsServer()) {
      throw QRunTimeError("Not a client");
    } else if(_state->my_server != from) {
      throw QRunTimeError("Not a server");
    }

    QHash<int, QByteArray> signatures;
    QByteArray cleartext;
    stream >> signatures >> cleartext;

    int server_length = GetGroup().GetSubgroup().Count();
    for(int idx = 0; idx < server_length; idx++) {
      if(!GetGroup().GetSubgroup().GetKey(idx)->Verify(cleartext,
            signatures[idx]))
      {
        Stop("Failed to verify signatures");
        return;
      }
    }

    _state->cleartext = cleartext;
    ProcessCleartext();

    _state_machine.StateComplete();
  }

  void BlogDropRound::HandleClientCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(!_server_state->allowed_clients.contains(from)) {
      throw QRunTimeError("Not allowed to submit a ciphertext");
    } else if(_server_state->client_ciphertexts.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray payload;
    stream >> payload;

    _server_state->client_ciphertexts[from] = payload;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->client_ciphertexts.count()
      << "expecting" << _server_state->allowed_clients.count();

    if(_server_state->allowed_clients.count() ==
        _server_state->client_ciphertexts.count())
    {
      _state_machine.StateComplete();
    } 
  }

  void BlogDropRound::HandleServerClientList(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have client list");
    }

    QHash<Id,QByteArray> remote_ctexts;
    stream >> remote_ctexts;

    _server_state->handled_servers.insert(from);

    // Make sure there are no overlaps in their list and our list
    QSet<Id> mykeys = _server_state->client_ciphertexts.keys().toSet();
    QSet<Id> theirkeys = remote_ctexts.keys().toSet();

    // Don't add in our own ciphertexts, since we already have them
    if(from != GetLocalId()) {

      // For now, we only allow clients to submit the same ciphertext
      // to a single server
      if((mykeys & theirkeys).count() != 0) {
        throw QRunTimeError("Client submitted ciphertexts to multiple servers");
      }

      _server_state->client_ciphertexts.unite(remote_ctexts);
    }

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received client list from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::HandleServerCiphertext(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have ciphertext");
    }

    QByteArray ciphertext;
    stream >> ciphertext;

    _server_state->handled_servers.insert(from);
    _server_state->server_ciphertexts[GetGroup().GetSubgroup().GetIndex(from)] = ciphertext;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received ciphertext from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::HandleServerValidation(const Id &from, QDataStream &stream)
  {
    if(!IsServer()) {
      throw QRunTimeError("Not a server");
    } else if(!GetGroup().GetSubgroup().Contains(from)) {
      throw QRunTimeError("Not a server");
    }

    Q_ASSERT(_server_state);

    if(_server_state->handled_servers.contains(from)) {
      throw QRunTimeError("Already have signature.");
    }

    QByteArray signature;
    stream >> signature;

    if(!GetGroup().GetSubgroup().GetKey(from)->
        Verify(_state->cleartext, signature))
    {
      throw QRunTimeError("Siganture doesn't match.");
    }

    _server_state->handled_servers.insert(from);
    _server_state->signatures[GetGroup().GetSubgroup().GetIndex(from)] = signature;

    qDebug() << GetGroup().GetIndex(GetLocalId()) << GetLocalId().ToString() <<
      ": received validation from" << GetGroup().GetIndex(from) <<
      from.ToString() << "Have" << _server_state->handled_servers.count()
      << "expecting" << GetGroup().GetSubgroup().Count();

    if(_server_state->handled_servers.count() == GetGroup().GetSubgroup().Count()) {
      _state_machine.StateComplete();
    }
  }

  void BlogDropRound::StartShuffle()
  {
    GetShuffleRound()->Start();
  }

  QPair<QByteArray, bool> BlogDropRound::GetShuffleData(int)
  {
    _state->shuffle_data = _state->anonymous_pk->GetByteArray();

    return QPair<QByteArray, bool>(_state->shuffle_data, false);
  }

  void BlogDropRound::ShuffleFinished()
  {
    if(!GetShuffleRound()->Successful()) {
      SetBadMembers(GetShuffleRound()->GetBadMembers());
      if(GetShuffleRound()->Interrupted()) {
        SetInterrupted();
      }
      Stop("ShuffleRound failed");
      return;
    }

    _state_machine.StateComplete();
  }

  void BlogDropRound::ProcessDataShuffle()
  {
    if(GetShuffleSink().Count() != _state->n_clients) {
      throw QRunTimeError("Did not receive a descriptor from everyone.");
    }

    int count = GetShuffleSink().Count();
    for(int idx = 0; idx < count; idx++) {
      QPair<QSharedPointer<ISender>, QByteArray> pair(GetShuffleSink().At(idx));

      QSharedPointer<const PublicKey> key(new PublicKey(_state->params, pair.second));

      if(!key->IsValid()) {
        throw QRunTimeError("Invalid key in shuffle.");
      }

      if(_state->shuffle_data == pair.second) {
        _state->my_idx = idx;
      }

      _state->slot_pks.append(key);

    }

    if(_state->slot_pks.count() != _state->n_clients) {
      throw QRunTimeError("Did not receive a key from all clients");
    }

    _state_machine.StateComplete();
  }

  void BlogDropRound::SubmitClientPublicKey()
  {
    // Sign the public key with my long-term key and send it 
    // to my server
    QByteArray packet;
    QDataStream pstream(&packet, QIODevice::WriteOnly);
    pstream << GetRoundId() 
      << _state->client_pk->ProveKnowledge(_state->client_sk)
      << _state->client_pk->GetByteArray();
    QByteArray signature = GetPrivateIdentity().GetSigningKey()->Sign(packet);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << CLIENT_PUBLIC_KEY << GetRoundId() << _state_machine.GetPhase() 
      << QPair<QByteArray, QByteArray>(packet, signature);

    VerifiableSend(IsServer() ? GetLocalId() : _state->my_server, payload);
  }

  void BlogDropRound::SubmitServerPublicKey()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_PUBLIC_KEY << GetRoundId() << _state_machine.GetPhase() 
      << _server_state->server_pk->GetByteArray()
      << _server_state->server_pk->ProveKnowledge(_server_state->server_sk)
      << _server_state->client_pub_packets;

    // Once we send the client PKs we can throw them away
    _server_state->client_pub_packets.clear();

    VerifiableBroadcast(payload);
  }

  void BlogDropRound::SubmitClientMasterPublicKey()
  {
    QList<QSharedPointer<const PublicKey> > server_pks;
    for(int i=0; i<GetGroup().GetSubgroup().Count(); i++) {
      server_pks.append(_state->server_pks[i]);
    }

    QList<QSharedPointer<const PublicKey> > commits;
    BlogDropUtils::GetMasterSharedSecrets(_state->params,
        _state->client_sk,
        server_pks,
        _state->master_client_sk,
        _state->master_client_pk,
        commits);

    QList<QByteArray> byte_commits;
    for(int i=0; i<commits.count(); i++) {
      byte_commits.append(
          _state->params->GetKeyGroup()->ElementToByteArray(commits[i]->GetElement()));
    }

    // Sign the master public key with my long-term key and send it 
    // to my server
    QByteArray packet;
    QDataStream pstream(&packet, QIODevice::WriteOnly);
    pstream 
      << GetRoundId() 
      << byte_commits;

    QByteArray signature = GetPrivateIdentity().GetSigningKey()->Sign(packet);

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << CLIENT_MASTER_PUBLIC_KEY << GetRoundId() << _state_machine.GetPhase() 
      << QPair<QByteArray, QByteArray>(packet, signature);

    VerifiableSend(IsServer() ? GetLocalId() : _state->my_server, payload);
  }

  void BlogDropRound::SubmitServerMasterPublicKey()
  {
    QList<QSharedPointer<const PublicKey> > client_pks;
    for(int i=0; i<GetGroup().Count(); i++) {
      client_pks.append(_state->client_pks[GetGroup().GetId(i)]);
    }

    QList<QSharedPointer<const PublicKey> > commits;
    BlogDropUtils::GetMasterSharedSecrets(_state->params,
        _server_state->server_sk,
        client_pks,
        _server_state->master_server_sk,
        _server_state->master_server_pk,
        commits);

    QList<QByteArray> byte_commits;
    for(int i=0; i<commits.count(); i++) {
      byte_commits.append(
          _state->params->GetKeyGroup()->ElementToByteArray(commits[i]->GetElement()));
    }

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_MASTER_PUBLIC_KEY << GetRoundId() << _state_machine.GetPhase() 
      << _server_state->master_server_pk->GetByteArray()
      << byte_commits
      << _server_state->client_master_pub_packets;

    // Once we send the client PKs we can throw them away
    _server_state->client_master_pub_packets.clear();

    VerifiableBroadcast(payload);
  }


  void BlogDropRound::PrepareForBulk()
  {
    // If we're using one of the hashing schemes, we need to do
    // key exchange to set up the session 
    if(UsesHashingGenerator()) {
      for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
        for(int client_idx=0; client_idx<GetGroup().Count(); client_idx++) {
          if(_state->commit_matrix_servers[server_idx][client_idx]->GetElement() != 
              _state->commit_matrix_clients[client_idx][server_idx]->GetElement()) {
            /*
            qDebug() << "commit S" << server_idx << client_idx 
              << _state->params->GetKeyGroup()->ElementToByteArray(
                  _state->commit_matrix_servers[server_idx][client_idx]->GetElement()).toHex();
            qDebug() << "commit C" << server_idx << client_idx 
              << _state->params->GetKeyGroup()->ElementToByteArray(
                  _state->commit_matrix_clients[client_idx][server_idx]->GetElement()).toHex();
                  */
            Stop(QString("Client %1 and server %2 disagree on commit").arg(client_idx).arg(server_idx));
            return;
          }
        }
      }

      for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
        PublicKeySet set(_state->params, _state->commit_matrix_servers[server_idx]);
        _state->master_server_pks[server_idx] = QSharedPointer<const PublicKey>(
              new PublicKey(_state->params, set.GetElement())); 
      }

      for(int client_idx=0; client_idx<GetGroup().Count(); client_idx++) {
        PublicKeySet set(_state->params, _state->commit_matrix_clients[client_idx]);
        _state->master_client_pks[GetGroup().GetId(client_idx)] = QSharedPointer<const PublicKey>(
              new PublicKey(_state->params, set.GetElement())); 
      }
    } else {
      _state->master_client_sk = _state->client_sk;
      _state->master_client_pk = _state->client_pk;
      _state->master_client_pks = _state->client_pks;
      _state->master_server_pks = _state->server_pks;

      Q_ASSERT(_state->master_client_pks.count() == GetGroup().Count());
      Q_ASSERT(_state->master_server_pks.count() == GetGroup().GetSubgroup().Count());

      if(IsServer()) {
        _server_state->master_server_sk = _server_state->server_sk;
        _server_state->master_server_pk = _server_state->server_pk;
      }
    }

    _state->master_server_pk_set = QSharedPointer<const PublicKeySet>(
        new PublicKeySet(_state->params, _state->master_server_pks.values()));

    _state->blogdrop_author = QSharedPointer<BlogDropAuthor>(
        new BlogDropAuthor(
              QSharedPointer<Parameters>(new Parameters(*_state->params)),
          _state->master_client_sk, 
          _state->master_server_pk_set, 
          _state->anonymous_sk));

    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      QSharedPointer<BlogDropClient> c(new BlogDropClient(
              QSharedPointer<Parameters>(new Parameters(*_state->params)),
            _state->master_client_sk,
            _state->master_server_pk_set, 
            _state->slot_pks[slot_idx])); 
      _state->blogdrop_clients.append(c);
    }

    if(IsServer()) {
      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        QSharedPointer<BlogDropServer> s(new BlogDropServer(
              QSharedPointer<Parameters>(new Parameters(*_state->params)),
          _server_state->master_server_sk,
          _state->master_server_pk_set, _state->slot_pks[slot_idx]));
        _server_state->blogdrop_servers.append(s);
      }
    }

    for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
      _state->master_server_pks_list.append(_state->master_server_pks[server_idx]);
    }

    // Dont need to hold the keys once the BlogDropClients
    // are initialized
    _state->slot_pks.clear();

    _state_machine.StateComplete();
    Utils::PrintResourceUsage(ToString() + " " + "beginning bulk");
  }

  void BlogDropRound::SubmitClientCiphertext()
  {
    QFuture<QByteArray> future = QtConcurrent::run(this, &BlogDropRound::GenerateClientCiphertext);
    QByteArray mycipher = future.result();
    //QByteArray mycipher = GenerateClientCiphertext();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << CLIENT_CIPHERTEXT << GetRoundId() << _state_machine.GetPhase()
      << mycipher;

    VerifiableSend(_state->my_server, payload);
  }

  QByteArray BlogDropRound::ComputeClientPlaintext()
  {
    QByteArray this_plaintext = _state->next_plaintext;
    const int nelms_orig = _state->blogdrop_author->GetParameters()->GetNElements();
    const int max_elms = 1024*64;

    const int len_length = 4;

    // The maximum length is (255 * bytes_per_element) - 1 byte for length
    _state->blogdrop_author->GetParameters()->SetNElements(max_elms);
    const int max_len = _state->blogdrop_author->MaxPlaintextLength() - len_length;
    _state->blogdrop_author->GetParameters()->SetNElements(nelms_orig);

    QPair<QByteArray, bool> pair = GetData(max_len);
    if(pair.first.size() > 0) {
      qDebug() << "Found a message of" << pair.first.size();
      _state->phases_since_transmission = 0;
    } else {
      _state->phases_since_transmission++;
    }

    _state->next_plaintext = pair.first;

    // First byte is number of elements
    int i;

    // Msg + 1 byte for length
    const int next_plaintext_len = _state->next_plaintext.count() + len_length;
    for(i=1; i<max_elms; i++) {
      _state->blogdrop_author->GetParameters()->SetNElements(i);
      if(next_plaintext_len <= _state->blogdrop_author->MaxPlaintextLength()) 
        break;
    }

    _state->blogdrop_author->GetParameters()->SetNElements(nelms_orig);


    // Slots stay open for 5 rounds
    const int threshold = 5;
    qDebug() << "Phases since xmit" << _state->phases_since_transmission << "thresh"
      << threshold;
    int slotlen;
    if(_state->phases_since_transmission > threshold) {
      qDebug() << "Closing slot!";
      slotlen = 0;
    } else {
      slotlen = i;
    }

    
    QByteArray lenbytes(4, '\0');
    Utils::Serialization::WriteInt(slotlen, lenbytes, 0);
    Q_ASSERT(lenbytes.count() == 4);
    QByteArray out = lenbytes + this_plaintext;


    qDebug() << "out" << out.count() << "max" << _state->blogdrop_author->MaxPlaintextLength();
    Q_ASSERT(out.count() <= _state->blogdrop_author->MaxPlaintextLength());
    return out;
  }

  QByteArray BlogDropRound::GenerateClientCiphertext()
  {
    QList<QByteArray> ctexts;

    QByteArray c;
    for(int slot_idx=0; slot_idx < _state->n_clients; slot_idx++) {
      qDebug() << "Generating for slot" << slot_idx;
      if(SlotIsOpen(slot_idx)) {

        if(slot_idx == _state->my_idx) {
          QByteArray m = ComputeClientPlaintext();
          
          if(!_state->blogdrop_author->GenerateAuthorCiphertext(c, m)) 
            qFatal("Could not generate author ciphertext");

        } else {
          c = _state->blogdrop_clients[slot_idx]->GenerateCoverCiphertext();
        }
      } else {
        qDebug() << "Client skipping closed slot" << slot_idx;
        c = QByteArray();
      }

      ctexts.append(c);
    }

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << ctexts;

    /* Return a serialized list of serialized ciphertexts */
    return out;
  }

  void BlogDropRound::SetOnlineClients()
  {
    _server_state->allowed_clients.clear();

    foreach(const QSharedPointer<Connection> &con,
        GetNetwork()->GetConnectionManager()->
        GetConnectionTable().GetConnections())
    {
      if(!GetGroup().Contains(con->GetRemoteId()) ||
          GetGroup().GetSubgroup().Contains(con->GetRemoteId()))
      {
        continue;
      }

      _server_state->allowed_clients.insert(con->GetRemoteId());
    }

    if(_server_state->allowed_clients.count() == 0) {
      _state_machine.StateComplete();
      return;
    }

    _server_state->expected_clients = _server_state->allowed_clients.count();
  }

  void BlogDropRound::ConcludeClientCiphertextSubmission(const int &)
  {
    qDebug() << "Client window has closed, unfortunately some client may not"
      << "have transmitted in time.";
    _state_machine.StateComplete();
  }

  void BlogDropRound::SubmitClientList()
  {
    QFuture<QByteArray> future = QtConcurrent::run(this, &BlogDropRound::GenerateClientCiphertext);
    QByteArray mycipher = future.result();
    //QByteArray mycipher = GenerateClientCiphertext();

    // Add my own ciphertext to the set
    _server_state->client_ciphertexts[GetLocalId()] = mycipher;

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLIENT_LIST << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->client_ciphertexts;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::GenerateServerCiphertext()
  {
    QList<QList<QByteArray> > by_slot;
    QList<QSharedPointer<const PublicKey> > client_pks;

    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      by_slot.append(QList<QByteArray>());
    }

    qDebug() << ToString() << "generating ciphertext for" <<
      _server_state->client_ciphertexts.count() << "out of" << GetGroup().Count();

    // For each user
    foreach(const Id& id, _server_state->client_ciphertexts.keys()) {

      QList<QByteArray> ctexts;
      QDataStream stream(_server_state->client_ciphertexts[id]);
      stream >> ctexts;

      if(ctexts.count() != _state->n_clients) {
        qFatal("Ciphertext vector has invalid length");
      }

      Q_ASSERT(_state->client_pks.contains(id));

      // For each slot
      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        if(SlotIsOpen(slot_idx)) {
          by_slot[slot_idx].append(ctexts[slot_idx]);
        } else {
          qDebug() << "Not adding client ciphertext to closed slot" << slot_idx;
        }
      }

      client_pks.append(_state->master_client_pks[id]);
      Q_ASSERT(!_state->master_client_pks[id].isNull());
    }

    Q_ASSERT(client_pks.count() == _state->n_clients);

    /*
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      if(!SlotIsOpen(slot_idx)) {
        Q_ASSERT(!by_slot[slot_idx].count());
      }
    }
    */

    QList<QByteArray> server_ctexts;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      QByteArray c;
      if(SlotIsOpen(slot_idx)) {
        Q_ASSERT(by_slot[slot_idx].count() == _state->n_clients);

        _server_state->blogdrop_servers[slot_idx]->AddClientCiphertexts(by_slot[slot_idx], client_pks);
        c = _server_state->blogdrop_servers[slot_idx]->CloseBin();
        qDebug() << "Creating server ciphertext for slot" << slot_idx;
      } else {
        qDebug() << "Not creating server ciphertext for closed slot" << slot_idx;
      }

      server_ctexts.append(c);
    }

    Q_ASSERT(server_ctexts.count() == _state->n_clients);

    QDataStream stream(&(_server_state->my_ciphertext), QIODevice::WriteOnly);
    stream << server_ctexts;
  }

  void BlogDropRound::SubmitServerCiphertext()
  {
    QFuture<void> future = QtConcurrent::run(this, &BlogDropRound::GenerateServerCiphertext);
    future.waitForFinished();
    //GenerateServerCiphertext();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CIPHERTEXT << GetRoundId() <<
      _state_machine.GetPhase() << _server_state->my_ciphertext;

    VerifiableBroadcastToServers(payload);
  }

  QByteArray BlogDropRound::GenerateServerValidation()
  {
    QList<QList<QByteArray> > by_slot;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      by_slot.append(QList<QByteArray>());
    }

    for(int server_idx=0; server_idx<GetGroup().GetSubgroup().Count(); server_idx++) {
      QList<QByteArray> server_list;
      QDataStream stream(_server_state->server_ciphertexts[server_idx]);
      stream >> server_list;

      if(server_list.count() != _state->n_clients) {
        qFatal("Server submitted ciphertext list of wrong length");
      }

      for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
        by_slot[slot_idx].append(server_list[slot_idx]);
      }
    }

    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      if(SlotIsOpen(slot_idx)) {
        if(!_server_state->blogdrop_servers[slot_idx]->AddServerCiphertexts(
                by_slot[slot_idx],
                _state->master_server_pks_list)) {
              qFatal("Server submitted invalid ciphertext");
          }
      } else {
        qDebug() << "Not adding server ciphertext to closed slot" << slot_idx;
      }
    }

    QList<QByteArray> plaintexts;
    for(int slot_idx=0; slot_idx<_state->n_clients; slot_idx++) {
      QByteArray plain;

      if(SlotIsOpen(slot_idx)) {
        if(!_server_state->blogdrop_servers[slot_idx]->RevealPlaintext(plain)) {
          qFatal("Could not decode plaintext message. Maybe bad anon author?");
        }

        // 4 bytes in an int
        const int slot_length = Utils::Serialization::ReadInt(plain, 0);

        if(!slot_length) {
          qDebug() << "Closing slot" << slot_idx;
          _state->slots_open[slot_idx] = false;
        } else {
          qDebug() << "Next nelms:" << slot_length;
          _state->slots_open[slot_idx] = true;
          _server_state->blogdrop_servers[slot_idx]->GetParameters()->SetNElements(slot_length);
        }
      } else {
        qDebug() << "Not decoding message for closed slot" << slot_idx;
      }

      plaintexts.append(plain);
      qDebug() << "Decoding message" << plain.toHex();
    }

    QDataStream pstream(&(_state->cleartext), QIODevice::WriteOnly);
    pstream << plaintexts;

    return GetPrivateIdentity().GetSigningKey()->Sign(_state->cleartext);
  }

  void BlogDropRound::SubmitValidation()
  {
    QFuture<QByteArray> future = QtConcurrent::run(this, 
        &BlogDropRound::GenerateServerValidation);
    QByteArray signature = future.result();
    //QByteArray signature = GenerateServerValidation();

    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_VALIDATION << GetRoundId() <<
      _state_machine.GetPhase() << signature;

    VerifiableBroadcastToServers(payload);
  }

  void BlogDropRound::PushCleartext()
  {
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream << SERVER_CLEARTEXT << GetRoundId() << _state_machine.GetPhase()
      << _server_state->signatures << _server_state->cleartext;

    VerifiableBroadcastToClients(payload);
    ProcessCleartext();
    _state_machine.StateComplete();
  }

  void BlogDropRound::ProcessCleartext()
  {
    QList<QByteArray> plaintexts;
    QDataStream stream(_state->cleartext);
    stream >> plaintexts;

    for(int slot_idx=0; slot_idx<plaintexts.count(); slot_idx++) {
      if(!SlotIsOpen(slot_idx)) {
        //qDebug() << "Skipping closed slot" << slot_idx;
        continue;
      }

      // An int is 4 bytes long
      const int len_length = 4;
      if(!plaintexts[slot_idx].isEmpty() && plaintexts[slot_idx].count() > len_length) {
        qDebug() << "Pushing cleartext of length" << plaintexts[slot_idx].mid(len_length).count();
        PushData(GetSharedPointer(), plaintexts[slot_idx].mid(len_length)); 
      }

      const int slot_length = Utils::Serialization::ReadInt(plaintexts[slot_idx], 0);
      if(!slot_length) {
        //qDebug() << "Closing slot" << slot_idx;
        _state->slots_open[slot_idx] = false;
      } else {
        //qDebug() << "Next nelms:" << slot_length;
        _state->slots_open[slot_idx] = true;
        _state->blogdrop_clients[slot_idx]->GetParameters()->SetNElements(slot_length);
        if(slot_idx == _state->my_idx) {
          _state->blogdrop_author->GetParameters()->SetNElements(slot_length);
        }
      }
    }
  }

  bool BlogDropRound::SlotIsOpen(int slot_idx)
  {
//    qDebug() << "SlotIsOpen always" << _state->always_open;
    return (_state->slots_open[slot_idx] || slot_idx == _state->always_open);
  }

}
}
