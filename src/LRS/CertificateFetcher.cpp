#include <QHostAddress>
#include <QSslKey>

#include "CertificateFetcher.hpp"
#include "FactorProof.hpp"
#include "RingSignature.hpp"
#include "SchnorrProof.hpp"

namespace Dissent {
namespace LRS {

  CertificateFetcher::CertificateFetcher(QByteArray msg) :
    _msg(msg) 
  {
    QObject::connect(this, SIGNAL(HaveAllCertificates()), this, SLOT(SignMessage()));
  }

  CertificateFetcher::~CertificateFetcher() {}


  void CertificateFetcher::Fetch(QList<QString> hosts, QList<quint16> ports)
  {
    Q_ASSERT(hosts.count() == ports.count());

    _sockets.clear();
    _certs.clear();
    for(int i=0; i<hosts.count(); i++) {
      QSslSocket *socket = new QSslSocket();
      QObject::connect(socket, SIGNAL(encrypted()), this, SLOT(HaveCertificate()));
      QObject::connect(socket, SIGNAL(error(QAbstractSocket::SocketError)), 
          this, SLOT(SocketError(QAbstractSocket::SocketError)));

      socket->connectToHostEncrypted(hosts[i], ports[i]);
      _sockets.append(socket);
    }
  }

  void CertificateFetcher::SocketError(QAbstractSocket::SocketError)
  {
    QSslSocket *socket = (QSslSocket*)sender();
    if(!socket) {
      qWarning() << "SocketError made invalid cast";
      return;
    }
    
    qWarning() << "Socket error" << socket->errorString();
    _certs.append(QSslCertificate());
    socket->close();
    socket->deleteLater();
  }

  void CertificateFetcher::HaveCertificate()
  {
    QSslSocket *socket = (QSslSocket*)sender();
    qDebug() << "Got cert from" << socket->peerAddress();

    if(!socket) {
      qWarning() << "NULL socket found";
      _certs.append(QSslCertificate());
    } else {
      _certs.append(socket->peerCertificate());
      socket->close();
      socket->deleteLater();
    }

    if(_certs.count() == _sockets.count()) {
      emit HaveAllCertificates();
    }
  }

  void CertificateFetcher::SignMessage()
  {
    qDebug() << "Have all certs. Starting to sign";

    QList<QSharedPointer<SigmaProof> > sigmas;
    const QByteArray context = "abcd";

    // Put the author in slot zero
    sigmas.append(QSharedPointer<SchnorrProof>(new SchnorrProof(context)));

    for(int i=0; i<_certs.count(); i++) {
      if(_certs[i].isNull()) {
        qDebug() << i << "Skipping empty cert";
        continue;
      }
      qDebug() << i << _certs[i];
      qDebug() << i << _certs[i].publicKey();

      sigmas.append(QSharedPointer<FactorProof>(new FactorProof(context, _certs[i].publicKey())));
    }

    RingSignature ring(context, sigmas, 0);

    emit Signed(ring.Sign(_msg));
  }

}
}
