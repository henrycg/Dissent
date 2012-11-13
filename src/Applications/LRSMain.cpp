
#include <QSslSocket>
#include <QSsl>

#include "Dissent.hpp"

int main(int argc, char **argv) {
  QCoreApplication qca(argc, argv);

  QTextStream out(stdout, QIODevice::WriteOnly);

  QList<QString> sites;
  sites << "www.yale.edu";
  sites << "www.google.com";
  sites << "mail.google.com";
  sites << "www.amazon.com";
  sites << "www.mit.edu";
  sites << "www.verisign.com";
  /*
  sites << "www.dell.com";
  sites << "www.softlayer.com";
  sites << "www.berkeley.edu";
  sites << "www.yahoo.com";
  */

  QList<quint16> ports;
  for(int i=0; i<sites.count(); i++) {
    ports << 443;
  }

  QByteArray msg = "The secret message";
  CertificateFetcher *c = new CertificateFetcher(msg);

  QObject::connect(c, SIGNAL(Signed(QByteArray)), &qca, SLOT(quit()));
  c->Fetch(sites, ports);

  return QCoreApplication::exec();
}

