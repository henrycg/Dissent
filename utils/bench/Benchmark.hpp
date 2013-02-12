#ifndef _DISSENT_UTILS_BENCH_BENCHMARK_H_GUARD
#define _DISSENT_UTILS_BENCH_BENCHMARK_H_GUARD

#include <qcoreapplication.h>
#include <gtest/gtest.h>

#include "Dissent.hpp"

namespace Dissent {
namespace Benchmarks {
  void ComputeSecrets(QSharedPointer<const Parameters> params, 
      const QList<QSharedPointer<const PrivateKey> > &client_sks_in,
      const QList<QSharedPointer<const PrivateKey> > &server_sks_in,
      const QList<QSharedPointer<const PublicKey> > &client_pks_in,
      const QList<QSharedPointer<const PublicKey> > &server_pks_in,
      QList<QSharedPointer<const PrivateKey> > &client_sks_out,
      QList<QSharedPointer<const PrivateKey> > &server_sks_out,
      QList<QSharedPointer<const PublicKey> > &client_pks_out,
      QList<QSharedPointer<const PublicKey> > &server_pks_out);
}
}

#endif
