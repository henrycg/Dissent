#include <algorithm>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Network.hpp"
#include "Crypto/Serialization.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"

#include "Session.hpp"

namespace Dissent {
namespace Anonymity {
  bool Session::EnableLogOffMonitor = true;

  Session::Session(const QSharedPointer<GroupHolder> &group_holder,
      const PrivateIdentity &ident, const Id &session_id,
      QSharedPointer<Network> network, CreateRound create_round) :
    _group_holder(group_holder),
    _ident(ident),
    _session_id(session_id),
    _network(network),
    _create_round(create_round),
    _current_round(0),
    _prepared(new ResponseHandler(this, "Prepared")),
    _registered(new ResponseHandler(this, "Registered")),
    _get_data_cb(this, &Session::GetData),
    _round_idx(0),
    _prepare_waiting(false),
    _registering(IsLeader())
  {
    QVariantHash headers = _network->GetHeaders();
    headers["session_id"] = _session_id.GetByteArray();
    _network->SetHeaders(headers);
    _network->SetMethod("SM::Data");

    if(IsLeader()) {
      AddMember(GetPublicIdentity(_ident));
    }

    foreach(const QSharedPointer<Connection> con,
        _network->GetConnectionManager()->GetConnectionTable().GetConnections())
    {
      QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
          this, SLOT(HandleDisconnect()));
    }

    QObject::connect(_network->GetConnectionManager().data(),
        SIGNAL(NewConnection(const QSharedPointer<Connection> &)),
        this, SLOT(HandleConnection(const QSharedPointer<Connection> &)));
  }

  Session::~Session()
  {
    // If SessionManager is being destructed causing this to be destructed and
    // this hasn't stopped, the Stopping signal will cause a nasty segfault
    // into a partially decomposed SessionManager
    QObject::disconnect(this, 0, 0, 0);
    Stop();
  }

  void Session::OnStart()
  {
    qDebug() << _ident.GetLocalId() << "Session started:" << _session_id;

    if(!_registering && (_network->GetConnection(GetGroup().GetLeader()) ||
          ((GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup) &&
           (_network->GetConnectionManager()->GetConnectionTable().GetConnections().count() > 1))))
    {
      Register();
    }

    if(IsLeader()) {
      Dissent::Utils::TimerCallback *cb =
        new Dissent::Utils::TimerMethod<Session, int>(this,
            &Session::CheckLogOffTimes, 0);

      _check_log_off_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb,
          LogOffCheckPeriod, LogOffCheckPeriod);
    }
  }

  void Session::OnStop()
  {
    _check_log_off_event.Stop();
    _register_event.Stop();
    _prepare_event.Stop();

    QObject::disconnect(this, SLOT(HandleDisconnect()));

    if(!_current_round.isNull()) {
      QObject::disconnect(_current_round.data(), SIGNAL(Finished()), this,
          SLOT(HandleRoundFinished()));
      _current_round->Stop("Session stopped");
    }

    emit Stopping();
  }

  bool Session::CheckGroup()
  {
    Dissent::Connections::ConnectionTable &ct =
      _network->GetConnectionManager()->GetConnectionTable();

    if(GetGroup().Count() < MinimumRoundSize) {
      qDebug() << "Not enough peers in group to support an anonymous session,"
        "need" << (GetGroup().Count() - MinimumRoundSize) << "more";
      return false;
    }

    const Group &group = GetGroup();
    if(group.GetSubgroupPolicy() == Group::ManagedSubgroup) {
      if(group.GetSubgroup().Contains(_ident.GetLocalId())) {
        foreach(const PublicIdentity &gc, group.GetSubgroup()) {
          if(ct.GetConnection(gc.GetId()) == 0) {
            qDebug() << "Missing a subgroup connection.";
            return false;
          }
        }
      } else {
        bool found = false;
        foreach(const QSharedPointer<Connection> &con, ct.GetConnections()) {
          if(group.GetSubgroup().Contains(con->GetRemoteId())) {
            found = true;
            break;
          }
        }
        if(!found) {
          qDebug() << "Missing a subgroup connection.";
          return false;
        }
      }
      return true;
    } else {
      bool good = true;
      foreach(const PublicIdentity &gc, group) {
        if(!ct.GetConnection(gc.GetId())) {
          qDebug() << "Missing a connection" << gc.GetId();
          good = false;
        }
      }

      return good;
    }
  }

  void Session::Register(const int &)
  {
    _registering = true;
    QVariantHash container;
    container["session_id"] = _session_id.GetByteArray();

    QByteArray ident;
    QDataStream stream(&ident, QIODevice::WriteOnly);
    stream << GetPublicIdentity(_ident);
    container["ident"] = ident;

    _network->SendRequest(GetGroup().GetLeader(), "SM::Register", container,
        _registered, true);
  }

  void Session::Registered(const Response &response)
  {
    if(Stopped()) {
      return;
    }

    if(response.Successful() && response.GetData().toBool()) {
      qDebug() << _ident.GetLocalId() << "registered and waiting to go.";
      return;
    }

    if(!_register_event.Stopped()) {
      qDebug() << "Almost started two registration attempts simultaneously!";
      return;
    }

    int delay = 5000;
    if(response.GetErrorType() == Response::Other) {
      delay = 60000;
    }
    qDebug() << "Unable to register due to" << response.GetError() <<
      "Trying again later.";

    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this, &Session::Register, 0);
    _register_event = Dissent::Utils::Timer::GetInstance().QueueCallback(cb, delay);
  }

  void Session::HandleRegister(const Request &request)
  {
    if(!IsLeader()) {
      qWarning() << "Received a registration message when not a leader.";
      request.Failed(Response::WrongDestination, "Not the leader");
      return;
    } else if(!Started()) {
      qDebug() << "Received a registration message when not started.";
      request.Failed(Response::InvalidInput, "Session not started");
      return;
    }

    QDataStream stream(request.GetData().toHash().value("ident").toByteArray());
    PublicIdentity ident;
    stream >> ident;

    if(!ident.GetVerificationKey()->IsValid()) {
      qWarning() << "Received a registration request with invalid credentials";
      request.Failed(Response::InvalidInput, "PrivateIdentity do not match Id");
      return;
    }

    if(!AllowRegistration(request.GetFrom(), ident)) {
      qDebug() << "Peer," << ident << ", has connectivity problems," <<
       "deferring registration until later.";
      request.Failed(Response::Other,
          "Unable to register at this time, try again later.");
      return;
    }

    qDebug() << "Received a valid registration message from:" << ident;
    _last_registration = Dissent::Utils::Time::GetInstance().CurrentTime();

    AddMember(ident);
    request.Respond(true);

    CheckRegistration();
  }

  bool Session::AllowRegistration(const QSharedPointer<ISender> &,
      const PublicIdentity &ident)
  {
    return !EnableLogOffMonitor || !_log_off_time.contains(ident.GetId());
  }

  void Session::CheckLogOffTimes(const int &)
  {
    qint64 cleared = Utils::Time::GetInstance().MSecsSinceEpoch() - LogOffPeriod;
    foreach(const Id &id, _log_off_time.keys()) {
      if(_log_off_time[id] < cleared) {
        _log_off_time.remove(id);
      }
    }
  }

  void Session::CheckRegistration()
  {
    QDateTime start_time;

    if(!_current_round || _current_round->Stopped()) {
      start_time = _last_registration.addMSecs(InitialPeerJoinDelay);
    } else if(_prepare_event.Stopped()) {
      QDateTime to_use = _current_round->GetCreateTime();
      if(_current_round->Started()) {
        to_use = _current_round->GetStartTime();
      }
      start_time = to_use.addMSecs(RoundRunningPeerJoinDelay);
    } else {
      return;
    }

    _prepare_event.Stop();
    Dissent::Utils::TimerCallback *cb =
      new Dissent::Utils::TimerMethod<Session, int>(this,
          &Session::CheckRegistrationCallback, 0);

    QDateTime ctime = Dissent::Utils::Time::GetInstance().CurrentTime();
    qint64 next = ctime.msecsTo(start_time);
    if(next < 0) {
      next = 0;
    }

    _prepare_event = Dissent::Utils::Timer::GetInstance().QueueCallback(
        cb, next);
  }

  void Session::CheckRegistrationCallback(const int &)
  {
    if(_current_round.isNull() || !_current_round->Started() ||
          _current_round->Stopped())
    {
      SendPrepare();
    } else {
      qDebug() << "Letting the current round know that a peer joined event occurred.";
      _current_round->PeerJoined();
    }
  }

  bool Session::SendPrepare()
  {
    if(!CheckGroup()) {
      qDebug() << "All peers registered and ready but lack sufficient peers";
      return false;
    }

    Id round_id(Id::Zero().GetInteger() + _round_idx++);

    QVariantHash msg;
    msg["session_id"] = _session_id.GetByteArray();
    msg["round_id"] = round_id.GetByteArray();
    msg["interrupt"] = _current_round.isNull() ?
      true : _current_round->Interrupted();

    if(GetGroup() != _shared_group) {
      _shared_group = GetGroup();
      QByteArray group;
      QDataStream stream(&group, QIODevice::WriteOnly);
      stream << _shared_group;
      msg["group"] = group;
    }

    qDebug() << "Sending prepare for round" << round_id <<
      "new group:" << msg.contains("group");

    _prepared_peers.clear();
    _unprepared_peers = _registered_peers;
    foreach(const Id &id, _registered_peers) {
      _network->SendRequest(id, "SM::Prepare", msg, _prepared);
    }

    NextRound(round_id);
    return true;
  }

  void Session::HandlePrepare(const Request &request)
  {
    if(_prepare_waiting) {
      _prepare_waiting = false;
    }

    QVariantHash msg = request.GetData().toHash();

    if(!_current_round.isNull() && !_current_round->Stopped() &&
        _current_round->Started())
    {
      _prepare_waiting = true;
      _prepare_request = request;
      if(msg.value("interrupt").toBool()) {
        _current_round->Stop("Round interrupted.");
      }
      return;
    }

    QByteArray brid = msg.value("round_id").toByteArray();
    if(brid.isEmpty()) {
      qDebug() << "HandlePrepare: Invalid round id";
      return;
    }

    Id round_id(brid);

    if(msg.contains("group")) {
      QDataStream stream(msg.value("group").toByteArray());
      Group group;
      stream >> group;
      qDebug() << "Prepare contains new group. I am present:" <<
        group.Contains(_ident.GetLocalId());
      _group_holder->UpdateGroup(group);
    }

    if(!CheckGroup()) {
      qDebug() << "Received a prepare message but lack of sufficient peers";
      _prepare_waiting = true;
      _prepare_request = request;
      return;
    }

    NextRound(round_id);
    request.Respond(brid);
    _prepare_request = Request();
  }

  void Session::Prepared(const Response &response)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      response.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a prepared message from a non-IOverlaySender:" <<
        response.GetFrom()->ToString();
      return;
    } else if(!GetGroup().Contains(sender->GetRemoteId())) {
      qWarning() << "Received a prepared message from a non-group member:" <<
        response.GetFrom()->ToString();
      return;
    }

    Q_ASSERT(_current_round);
    Id round_id(response.GetData().toByteArray());
    if(_current_round->GetRoundId() != round_id) {
      qDebug() << "Received a prepared message from the wrong round.  RoundId:" <<
        round_id << "from" << response.GetFrom()->ToString();
      return;
    }

    // Were we waiting on this one?
    if(_unprepared_peers.remove(sender->GetRemoteId()) > 0) {
      _prepared_peers.append(sender->GetRemoteId());
      CheckPrepares();
    }
  }

  void Session::CheckPrepares()
  {
    if(_current_round->Stopped() || _current_round->Started()) {
      return;
    }

    if(_unprepared_peers.size() > 0) {
      qDebug() << "Waiting on" << _unprepared_peers.size() <<
        "more prepared responses.";
      if(_unprepared_peers.size() < 5) {
        qDebug() << "Waiting on:" << _unprepared_peers.keys();
      }
      return;
    }

    QVariantHash msg;
    msg["session_id"] = _session_id.GetByteArray();
    msg["round_id"] = GetCurrentRound()->GetRoundId().GetByteArray();
    foreach(const Id &id, _prepared_peers) {
      _network->SendNotification(id, "SM::Begin", msg);
    }
  }

  void Session::HandleBegin(const Request &notification)
  {
    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a begin from a non-IOverlaySender." <<
        notification.GetFrom()->ToString();
      return;
    }

    if(GetGroup().GetLeader() != sender->GetRemoteId()) {
      qWarning() << "Received a begin from someone other than the leader:" <<
        notification.GetFrom()->ToString();
      return;
    }

    if(_current_round.isNull()) {
      qWarning() << "Received a begin without having a valid round...";
      return;
    }

    Id round_id(notification.GetData().toHash().value("round_id").toByteArray());
    if(_current_round->GetRoundId() != round_id) {
      qWarning() << "Received a begin for a different round, expected:" <<
        _current_round->GetRoundId() << "got:" << round_id;
      return;
    }

    qDebug() << "Session" << ToString() << "starting round" <<
      _current_round->ToString() << "started" << _current_round->Started();
    emit RoundStarting(_current_round);
    _current_round->Start();
  }

  void Session::HandleRoundFinished()
  {
    Round *round = qobject_cast<Round *>(sender());
    if(round != _current_round.data()) {
      qWarning() << "Received an awry Round Finished notification";
      return;
    }

    qDebug() << "Session" << ToString() << "round" << _current_round <<
      "finished due to" << _current_round->GetStoppedReason();

    emit RoundFinished(_current_round);

    if(Stopped()) {
      qDebug() << "Session stopped.";
      return;
    }

    const QVector<int> bad = _current_round->GetBadMembers();
    if(_current_round->GetBadMembers().size()) {
      qWarning() << "Found some bad members...";
      if(IsLeader()) {
        Group group = GetGroup();
        foreach(int idx, _current_round->GetBadMembers()) {
          RemoveMember(group.GetId(idx));
          _bad_members.insert(GetGroup().GetId(idx));
        }
      }
    }

    if(IsLeader()) {
      CheckRegistration();
    } else if(_prepare_waiting) {
      HandlePrepare(_prepare_request);
    }
  }

  void Session::NextRound(const Id &round_id)
  {
    _current_round = _create_round(GetGroup(), _ident, round_id,
        _network, _get_data_cb);

    qDebug() << "Session" << ToString() << "preparing new round" <<
      _current_round;

    _current_round->SetSink(this);
    QObject::connect(_current_round.data(), SIGNAL(Finished()), this,
        SLOT(HandleRoundFinished()));
  }

  void Session::Send(const QByteArray &data)
  {
    if(Stopped()) {
      qWarning() << "Session is stopped.";
      return;
    }

    _send_queue.enqueue(data);
  }

  void Session::IncomingData(const Request &notification)
  {
    if(!_current_round.isNull()) {
      _current_round->IncomingData(notification);
    } else {
      qWarning() << "Received a data message without having a valid round.";
    }
  }

  void Session::HandleConnection(const QSharedPointer<Connection> &con)
  {
    if(!_registering && ((GetGroup().GetLeader() == con->GetRemoteId()) ||
        (GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup)))
    {
      Register();
    }

    QObject::connect(con.data(), SIGNAL(Disconnected(const QString &)),
        this, SLOT(HandleDisconnect()));

    if(_prepare_waiting && CheckGroup()) {
      HandlePrepare(_prepare_request);
    }
  }

  void Session::HandleDisconnect()
  {
    if(Stopped()) {
      return;
    }

    Connection *con = qobject_cast<Connection *>(sender());
    const Id &remote_id = con->GetRemoteId();

    if(IsLeader()) {
      HandleDisconnect(remote_id);
      return;
    }

    if(GetGroup().GetLeader() == remote_id) {
      qWarning() << "Leader disconnected!";
      _registering = false;
    } else if((_network->GetConnectionManager()->
        GetConnectionTable().GetConnections().count() == 1) && !IsLeader())
    {
      _registering = false;
    } else if((GetGroup().GetSubgroupPolicy() != Group::ManagedSubgroup)
        || (GetGroup().GetSubgroup().Contains(_ident.GetLocalId())))
    {
      // Only let servers notify...
      QVariantHash container;
      container["session_id"] = _session_id.GetByteArray();
      container["remote_id"] = remote_id.GetByteArray();
      _network->SendNotification(GetGroup().GetLeader(), "SM::Disconnect", container);
    }

    if(_current_round) {
      _current_round->HandleDisconnect(remote_id);
    }
  }

  void Session::LinkDisconnect(const Request &notification)
  {
    if(!IsLeader()) {
      qDebug() << "Arrived into handle disconnect even though not the leader.";
      return;
    }

    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qWarning() << "Received a LinkDisconnect from a non-IOverlaySender." <<
        sender->ToString();
      return;
    } else if(!GetGroup().Contains(sender->GetRemoteId())) {
      qWarning() << "Received a LinkDisconnect from a non-member." <<
        sender->GetRemoteId();
      return;
    }

    Id remote_id = Id(notification.GetData().toHash().value("remote_id").toByteArray());
    if((GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup)
        && (!GetGroup().GetSubgroup().Contains(sender->GetRemoteId())))
    {
      // Sent from a client, let the server report this...
      return;
    }

    HandleDisconnect(remote_id);
  }

  void Session::HandleDisconnect(const Id &remote_id)
  {
    if(!GetGroup().Contains(remote_id)) {
      return;
    }

    // This was a sponsored connection and we have no knowledge of it
    if(_network->GetConnection(remote_id) == 0) {
      _log_off_time[remote_id] = Utils::Time::GetInstance().MSecsSinceEpoch();
      RemoveMember(remote_id);
    }

    if(_current_round) {
      _current_round->HandleDisconnect(remote_id);
      CheckPrepares();
    }
  }

  void Session::AddMember(const PublicIdentity &gc)
  {
    if(!GetGroup().Contains(gc.GetId())) {
      bool subgroup = (GetGroup().GetSubgroupPolicy() == Group::ManagedSubgroup)
        && gc.GetSuperPeer();
      _group_holder->UpdateGroup(AddGroupMember(GetGroup(), gc, subgroup));
    }

    _registered_peers.insert(gc.GetId(), gc.GetId());
  }

  void Session::RemoveMember(const Id &id)
  {
    _group_holder->UpdateGroup(RemoveGroupMember(GetGroup(), id));
    _registered_peers.remove(id);
    _unprepared_peers.remove(id);
  }

  QPair<QByteArray, bool> Session::GetData(int max)
  {
    QByteArray data;

    // Discard all messages that are too big to send
    while(!_send_queue.isEmpty() && _send_queue.head().count() > max) {
      qWarning() << "Discarding oversized message" <<
        _send_queue.head().count() << "/" << max;
      _send_queue.dequeue();
    }

    // Pull messages off of queue until max length is reached
    // or queue is empty
    while(!_send_queue.isEmpty()) {
      if((_send_queue.head().count() + data.count()) <= max) {
        data.append(_send_queue.dequeue());
      } else {
        break;
      }
    }

    return QPair<QByteArray, bool>(data, !_send_queue.isEmpty());
  }
}
}
