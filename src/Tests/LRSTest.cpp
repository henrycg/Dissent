#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {

  class LRSProofTest : 
    public ::testing::TestWithParam<QSharedPointer<AbstractGroup::AbstractGroup> > {
  };

  TEST_P(LRSProofTest, SchnorrProve)
  {
    //SchnorrProof proto(GetParam());
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

  TEST_P(LRSProofTest, SchnorrProveFake)
  {
    //SchnorrProof proto(GetParam());
    QByteArray context = "abcd";
    SchnorrProof proto(context);

    for(int i=0; i<10; i++) {
      proto.SetWitness(0); 

      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST_P(LRSProofTest, SchnorrRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    for(int repeat=0; repeat<1; repeat++) {
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

  INSTANTIATE_TEST_CASE_P(LRS, LRSProofTest,
      ::testing::Values(
        IntegerGroup::GetGroup(IntegerGroup::TESTING_512),
        CppECGroup::GetGroup(ECParams::NIST_P192),
        OpenECGroup::GetGroup(ECParams::NIST_P192),
        BotanECGroup::GetGroup(ECParams::NIST_P192)));

  TEST(LRSProofTest, FactorProve)
  {
    const int n_bits = 512;
    FactorProof proof(n_bits, "abcd");
    for(int i=0; i<2; i++) {
      proof.GenerateCommit();
      proof.GenerateChallenge();

      proof.Prove();
      EXPECT_TRUE(proof.Verify());

      proof.Prove(QByteArray("short"));
      EXPECT_TRUE(proof.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorProveFake)
  {
    const int n_bits = 512;
    FactorProof proto(n_bits, "abcd");

    for(int i=0; i<20; i++) {
      proto.SetWitness(0); 

      proto.FakeProve();
      EXPECT_TRUE(proto.Verify(false));
    }
  }

  TEST(LRSProofTest, FactorRing)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    const int n_bits = 512;

    for(int repeat=0; repeat<1; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        list.append(QSharedPointer<SigmaProof>(new FactorProof(n_bits, "abcd")));
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

    const int n_bits = 2048;

    for(int repeat=0; repeat<5; repeat++) {
      int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
      int author_idx = Random::GetInstance().GetInt(0, count);
   
      QList<QSharedPointer<SigmaProof> > list;
      for(int j=0; j<count; j++) {
        // Mix Schnorr and Factor proofs
        list.append(
          Random::GetInstance().GetInt(0, 2) ? 
          QSharedPointer<SigmaProof>(new FactorProof(n_bits, "abcd")) : 
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

