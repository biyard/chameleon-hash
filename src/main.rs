use std::{fmt, time};

use num_bigint::{BigInt, ToBigUint};
use num_primes::{BigUint, Generator};
use num_traits::{One, Zero};

/// Chameleon hash function parameters
#[derive(Clone)]
pub struct ChameleonHash {
    p: BigUint,     // Large prime p
    q: BigUint,     // Order of the group (p = kq + 1)
    g: BigUint,     // Generator of order q
    x: BigUint,     // Private key (trapdoor)
    inv_x: BigUint, // Private key (trapdoor)
    y: BigUint,     // Public key y = g^x mod p
}

fn mod_inverse(x: &BigInt, n: &BigInt) -> Option<BigInt> {
    let (gcd, inv, _) = extended_gcd(x, n);

    // If gcd is not 1, inverse does not exist
    if gcd != BigInt::one() {
        return None;
    }

    // Ensure the inverse is positive
    let inv = (inv % n + n) % n;
    Some(inv)
}

/// Extended Euclidean Algorithm to find gcd and the coefficients for Bézout's identity.
/// It returns (gcd, x, y) such that gcd(a, b) = a*x + b*y.
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero());
    }

    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * y1;

    (gcd, x, y)
}

impl fmt::Display for ChameleonHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChameleonHash:\n  p: {}\n  q: {}\n  g: {}\n  x: {}\n  inv_x:{}\n  y: {}",
            self.p, self.q, self.g, self.x, self.inv_x, self.y
        )
    }
}

impl fmt::Debug for ChameleonHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ChameleonHash:\n  p: {}\n  q: {}\n  g: {}\n  x: {}\n  inv_x:{}\n  y: {}",
            self.p, self.q, self.g, self.x, self.inv_x, self.y
        )
    }
}

impl ChameleonHash {
    /// Generate new parameters for the chameleon hash
    pub fn new(bits: usize) -> Self {
        let (p,g) = match bits {
            2048 => ("12765995242756727635490723797563163751437833605075330119650674113830381914186234988200722415197225041462565133560520571201115222896675589315315978953036599172412527056891214506723766822793872006436865686336085841281197937151580443010913492857890851283927134046492031696210831165186194507466654022162900894683035366112291534825460498736358256085895052201524351249373839086274409593023852092454308550073406636882442195459836926217967645707140193824234076181935887646885118537375808887282500918782654654604064942811836451890630413004878387975493282283197882329232051742396976452646469346676518326619371455959820191837241"
                .parse::<BigUint>()
                     .unwrap(), 5.to_biguint().unwrap()),
            1024 => ("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007"
                .parse::<BigUint>()
                .unwrap(), 2.to_biguint().unwrap()),
            // 160 bits
            160 => ("1110993139090855285586132226382129815148739954519"
                .parse::<BigUint>()
                    .unwrap(), 5.to_biguint().unwrap()),
            bits => (Generator::safe_prime(bits), 5.to_biguint().unwrap()),
        } ;

        let one = BigUint::one();
        let two = &one + &one;

        let q = (&p - &one) / &two;
        // let g = 5.to_biguint().unwrap();

        let x = Generator::new_uint(q.bits() - 1);
        let y = g.modpow(&x, &p);
        let ix = BigInt::from_biguint(num_bigint::Sign::Plus, x.clone());
        let iq = BigInt::from_biguint(num_bigint::Sign::Plus, q.clone());
        let inv_x = mod_inverse(&ix, &iq)
            .expect("failed to compute inverse of x in q")
            .to_biguint()
            .expect("failed to convert inverse to BigUint");

        assert!(
            (&inv_x * &x) % &q == one,
            "failed to verify inverse of x in q: {}",
            (&inv_x * &x) % &q
        );

        ChameleonHash {
            p,
            q,
            g,
            x,
            y,
            inv_x,
        }
    }

    pub fn hash(&self, m: &BigUint, r: &BigUint) -> BigUint {
        let gm = self.g.modpow(m, &self.p);
        let yr = self.y.modpow(r, &self.p);
        (gm * yr) % &self.p
    }

    pub fn find_collision(&self, m1: &BigUint, r: &BigUint, m2: &BigUint) -> BigUint {
        let left = m1 + &self.q - m2;
        let left = left * &self.inv_x % &self.q;
        let left = left + r % &self.q;

        left % &self.q
    }

    pub fn public_keys(&self) -> (BigUint, BigUint, BigUint, BigUint) {
        (
            self.p.clone(),
            self.q.clone(),
            self.g.clone(),
            self.y.clone(),
        )
    }

    pub fn verify(
        (p, _q, g, y): (BigUint, BigUint, BigUint, BigUint),
        m: &BigUint,
        r: &BigUint,
        h: &BigUint,
    ) -> bool {
        let gm = g.modpow(m, &p);
        let yr = y.modpow(r, &p);
        let gh = (gm * yr) % &p;
        gh == *h
    }
}

fn test_chameleon_hash(bits: usize) {
    println!("Testing Chameleon Hash with {} bits", bits);
    let start = time::SystemTime::now();
    let t = time::SystemTime::now();
    let chameleon_hash = ChameleonHash::new(bits);
    println!(
        "Time elapsed(Setup): {:?}us",
        t.elapsed().unwrap().as_micros()
    );
    // println!("Chameleon hash: {:?}", chameleon_hash);

    let m1 = Generator::new_uint(chameleon_hash.q.bits() - 1);
    let r1 = Generator::new_uint(chameleon_hash.q.bits() - 1);

    let t = time::SystemTime::now();
    let hash1 = chameleon_hash.hash(&m1, &r1);
    println!(
        "Time elapsed(Hash): {:?}us",
        t.elapsed().unwrap().as_micros()
    );
    // println!("Hash of (m1({}), r1({})): {}", m1, r1, hash1);

    let t = time::SystemTime::now();
    assert!(
        ChameleonHash::verify(chameleon_hash.public_keys(), &m1, &r1, &hash1),
        "failed to verify hash"
    );
    println!(
        "Time elapsed(Verification): {:?}us",
        t.elapsed().unwrap().as_micros()
    );

    let m2 = Generator::new_uint(chameleon_hash.q.bits() - 1);
    let t = time::SystemTime::now();
    let r2 = chameleon_hash.find_collision(&m1, &r1, &m2);
    println!(
        "Time elapsed(Finding Collision): {:?}us",
        t.elapsed().unwrap().as_micros()
    );

    let t = time::SystemTime::now();
    let hash2 = chameleon_hash.hash(&m2, &r2);
    println!(
        "Time elapsed(Hash): {:?}us",
        t.elapsed().unwrap().as_micros()
    );

    // println!("Hash of (m2({}), r2({})): {}", m2, r2, hash2);

    println!(
        "Total time elapsed: {:?}us",
        start.elapsed().unwrap().as_micros()
    );

    assert_eq!(hash1, hash2, "Collision failed!");
    println!("");
}

fn main() {
    for bits in vec![160, 1024, 2048] {
        test_chameleon_hash(bits);
    }
}
