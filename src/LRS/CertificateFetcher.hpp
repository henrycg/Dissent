#ifndef DISSENT_LRS_CERTIFICATE_FETCHER_H_GUARD
#define DISSENT_LRS_CERTIFICATE_FETCHER_H_GUARD

#include <QSslCertificate>
#include <QSslSocket>

namespace Dissent {
namespace LRS {

  class CertificateFetcher : public QObject {

    Q_OBJECT

    public:

      /**
       * Constructor
       */
      CertificateFetcher(QByteArray msg);

      /**
       * Destructor
       */
      virtual ~CertificateFetcher();

      /**
       * Emits Finished when done
       */
      void Fetch(QList<QString> hosts, QList<quint16> ports);

      inline QList<QSslCertificate> GetCerificates() const { return _certs; }

    signals:

      void HaveAllCertificates();
      void Signed(QByteArray);

    private slots:

      void SocketError(QAbstractSocket::SocketError);
      void HaveCertificate();
      void SignMessage();

    private:

      QByteArray _msg;
      QList<QSslSocket*> _sockets;
      QList<QSslCertificate> _certs;

  };

}
}

#endif
