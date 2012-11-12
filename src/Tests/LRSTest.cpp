#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class LRSProofTest : 
    public ::testing::TestWithParam<QSharedPointer<AbstractGroup::AbstractGroup> > {
  };

  TEST(LRSProofTest, SchnorrProve)
  {
    QByteArray context = "abcd";
    SchnorrProof proto(context);

    for(int i=0; i<10; i++) {
      proto.GenerateCommit();
      proto.GenerateChallenge();
      proto.Prove();

      EXPECT_TRUE(proto.Verify());

      proto.Prove(QByteArray("short"));
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST(LRSProofTest, SchnorrProveFake)
  {
    QByteArray context = "abcd";
    SchnorrProof proto(context);

    for(int i=0; i<10; i++) {
      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST(LRSProofTest, SchnorrRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int repeat=0; repeat<5; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        list.append(QSharedPointer<SigmaProof>(new SchnorrProof("abcd")));
      }

      QByteArray msg(1024, '\0');
      rand->GenerateBlock(msg);

      RingSignature ring("abcd", list, author_idx);

      QByteArray sig = ring.Sign(msg);
      EXPECT_TRUE(ring.Verify(msg, sig));

      // Tweak one byte of the message
      msg[3] = !msg[3];
      EXPECT_FALSE(ring.Verify(msg, sig));
    }
  }

  TEST(LRSProofTest, FactorProve)
  {
    const int n_bits = 512;
    FactorProof proof("abcd", n_bits);
    for(int i=0; i<20; i++) {
      proof.GenerateCommit();
      proof.GenerateChallenge();

      proof.Prove();
      EXPECT_TRUE(proof.Verify());

      proof.Prove(QByteArray("short"));
      EXPECT_TRUE(proof.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorProveSerialized)
  {
    const int n_bits = 512;
    FactorProof proof("abcd", n_bits);
    for(int i=0; i<20; i++) {
      proof.GenerateCommit();
      proof.GenerateChallenge();
      proof.Prove();

      FactorProof ser("abcd", 
          proof.GetWitnessImage(),
          proof.GetLinkageTag(),
          proof.GetCommit(),
          proof.GetChallenge().GetByteArray(),
          proof.GetResponse());

      EXPECT_TRUE(ser.Verify());

      proof.Prove(QByteArray("short"));
      EXPECT_TRUE(proof.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorProveFake)
  {
    const int n_bits = 512;
    FactorProof proto("abcd", n_bits);

    for(int i=0; i<20; i++) {
      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    const int n_bits = 512;

    for(int repeat=0; repeat<5; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        list.append(QSharedPointer<SigmaProof>(new FactorProof("abcd", n_bits)));
      }

      QByteArray msg(1024, '\0');
      rand->GenerateBlock(msg);

      RingSignature ring("abcd", list, author_idx);

      QByteArray sig = ring.Sign(msg);
      EXPECT_TRUE(ring.Verify(msg, sig));

      // Tweak one byte of the message
      msg[3] = !msg[3];
      EXPECT_FALSE(ring.Verify(msg, sig));
    }
  }

  TEST(LRSProofTest, MixedRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    const int n_bits = 512;

    for(int repeat=0; repeat<1; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        // Mix Schnorr and Factor proofs
        list.append(
          Random::GetInstance().GetInt(0, 2) ? 
          QSharedPointer<SigmaProof>(new FactorProof("abcd", n_bits)) : 
          QSharedPointer<SigmaProof>(new SchnorrProof("abcd")));
      }

      QByteArray msg(1024, '\0');
      rand->GenerateBlock(msg);

      RingSignature ring("abcd", list, author_idx);

      QByteArray sig = ring.Sign(msg);
      EXPECT_TRUE(ring.Verify(msg, sig));

      // Tweak one byte of the message
      msg[3] = !msg[3];
      EXPECT_FALSE(ring.Verify(msg, sig));
    }
  }

}
}

