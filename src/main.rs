use curv::arithmetic::*;
use curv::elliptic::curves::*;

/// Pedersen Commitment:
/// compute c = mG + rH
/// where m is the commited value, G is the group generator,
/// H is a random point and r is a blinding value.
/// TO RUN:
/// cargo run --example pedersen_commitment -- CURVE_NAME
/// CURVE_NAME is any of the supported curves: i.e.:
/// cargo run --example pedersen_commitment -- ristretto
///
/// notice: this library includes also hash based commitments

const SECURITY_BITS: usize = 256;

pub fn ped_com<E: Curve>(message: &BigInt) {
    use curv::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
    use curv::cryptographic_primitives::commitments::traits::Commitment;

    let security_bits = 256;
    let blinding_factor = BigInt::sample(security_bits);
    let com = PedersenCommitment::<E>::create_commitment_with_user_defined_randomness(
        message,
        &blinding_factor,
    );

    println!(
        "\ncreated commitment with user defined randomness \n\n blinding_factor {} \n commitment: {:#?}",
        blinding_factor, com
    );
}

pub struct ElgamalCipher<E: Curve> {
    pub c1: Point<E>,
    pub c2: Point<E>,
}

pub struct ElgamalDecShare<E: Curve> {
    pub share: Point<E>,
    pub index: i32,
}

pub fn central_gen_thresh_key<E: Curve>(t: i32, n: i32) -> (Point<E>, Vec<Scalar<E>>) {
    let mut sks = Vec::new();
    let mut par = Vec::new();
    let g = Point::<E>::generator();
    for _ in 0..t {
        par.push(Scalar::<E>::random());
    }
    for i in 1..n + 1 {
        let r = eval_function(&par, i.into());
        sks.push(r);
    }
    (&par[0] * g, sks)
}

fn eval_function<E: Curve>(func_par: &[Scalar<E>], n: Scalar<E>) -> Scalar<E> {
    let mut result = BigInt::zero();
    let n_bigint = n.to_bigint();
    for (i, par) in func_par.iter().enumerate() {
        result += n_bigint.pow(i.try_into().unwrap()) * par.to_bigint();
    }
    Scalar::<E>::from_bigint(&result)
}

pub fn gen_key<E: Curve>() -> (Point<E>, Scalar<E>) {
    let g = Point::<E>::generator();
    let x = BigInt::sample(SECURITY_BITS);
    let x_scalar = Scalar::<E>::from(x);
    (&x_scalar * g, x_scalar)
}

pub fn elgamal_enc<E: Curve>(message: &Scalar<E>, pk: &Point<E>) -> ElgamalCipher<E> {
    let g = Point::<E>::generator();
    let k = BigInt::sample(SECURITY_BITS);
    let k_scalar = Scalar::<E>::from(k);
    let c1 = &k_scalar * g;
    let mg = message * g;
    let kp = &k_scalar * pk;
    let c2 = mg + kp;
    ElgamalCipher { c1, c2 }
}

pub fn elgamal_add<E: Curve>(ct1: &ElgamalCipher<E>, ct2: &ElgamalCipher<E>) -> ElgamalCipher<E> {
    let new_c1 = &ct1.c1 + &ct2.c1;
    let new_c2 = &ct1.c2 + &ct2.c2;
    ElgamalCipher {
        c1: new_c1,
        c2: new_c2,
    }
}

pub fn elgamal_dec_share<E: Curve>(
    ct: &ElgamalCipher<E>,
    sk_share: &Scalar<E>,
    index: i32,
) -> ElgamalDecShare<E> {
    let share = sk_share * &ct.c1;
    ElgamalDecShare { share, index }
}

pub fn combind_share<E: Curve>(
    ct: &ElgamalCipher<E>,
    shares: &[ElgamalDecShare<E>],
) -> Result<Scalar<E>, ()> {
    let indices: Vec<f64> = shares.iter().map(|share| share.index as f64).collect();
    let mut res_ct = Point::<E>::zero();
    for share in shares {
        let mut inter = 1f64;
        for j in &indices {
            if j == &(share.index as f64) {
                continue;
            }
            inter *= j / (j - &(share.index as f64));
        }
        let a = Scalar::<E>::from(inter as i32) * &share.share;
        res_ct = res_ct + a;
    }
    let result = &ct.c2 - res_ct;
    let g = Point::<E>::generator();
    for i in 1..1000 {
        let i_scalar = Scalar::<E>::from(i as i32);
        if &i_scalar * g == result {
            return Ok(i_scalar);
        }
    }
    Err(())
}

pub fn elgamal_dec<E: Curve>(ct: &ElgamalCipher<E>, sk: &Scalar<E>) -> Result<Scalar<E>, ()> {
    let m_xc1 = -sk * &ct.c1;
    let mg = &m_xc1 + &ct.c2;
    let g = Point::<E>::generator();
    for i in 1..1000 {
        let i_scalar = Scalar::<E>::from(i);
        if &i_scalar * g == mg {
            return Ok(i_scalar);
        }
    }
    Err(())
}

fn main() {
    // let message = "commit me!";
    // let message_bn = BigInt::from_bytes(message.as_bytes());
    // let curve_name = std::env::args().nth(1);
    // match curve_name.as_deref() {
    //     Some("secp256k1") => ped_com::<Secp256k1>(&message_bn),
    //     Some("ristretto") => ped_com::<Ristretto>(&message_bn),
    //     Some("ed25519") => ped_com::<Ed25519>(&message_bn),
    //     Some("bls12_381_1") => ped_com::<Bls12_381_1>(&message_bn),
    //     Some("bls12_381_2") => ped_com::<Bls12_381_2>(&message_bn),
    //     Some("p256") => ped_com::<Secp256r1>(&message_bn),
    //     Some(unknown_curve) => eprintln!("Unknown curve: {}", unknown_curve),
    //     None => eprintln!("Missing curve name"),
    // }

    // let (pk, sk) = gen_key::<Secp256k1>();
    // let m = BigInt::sample(SECURITY_BITS);
    // let m_scalar = Scalar::<Secp256k1>::from(103i32);
    // let ct = elgamal_enc(&m_scalar, &pk);

    // let m_scalar2 = Scalar::<Secp256k1>::from(100i32);
    // let ct2 = elgamal_enc(&m_scalar2, &pk);

    // let ct3 = elgamal_add::<Secp256k1>(&ct, &ct2);
    // let r = elgamal_dec(&ct, &sk).unwrap();
    // let big_r = r.to_bigint();
    // let r2 = elgamal_dec(&ct2, &sk).unwrap();
    // let big_r2 = r2.to_bigint();
    // let r3 = elgamal_dec(&ct3, &sk).unwrap();
    // let big_r3 = r3.to_bigint();

    let (pk, sks) = central_gen_thresh_key::<Secp256k1>(3, 5);
    let m_scalar = Scalar::<Secp256k1>::from(103i32);
    let ct = elgamal_enc(&m_scalar, &pk);
    let share1 = elgamal_dec_share(&ct, &sks[0], 1);
    let share2 = elgamal_dec_share(&ct, &sks[1], 2);
    let share3 = elgamal_dec_share(&ct, &sks[2], 3);

    let shares = &[share1, share2, share3];
    let r = combind_share(&ct, shares).unwrap();
    let big_r = r.to_bigint();
    println!("{}", big_r);

    // println!("{} + {} = {}", big_r, big_r2, big_r3);
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_eval_function() {
        //f(x) = 2+3x^1+4x^2
        let pars = &[
            Scalar::<Secp256k1>::from(2i32),
            Scalar::<Secp256k1>::from(3i32),
            Scalar::<Secp256k1>::from(4i32),
        ];

        //f(3) = 47
        let result = eval_function(pars, 3i32.into());
        assert_eq!(Scalar::<Secp256k1>::from(47i32), result);

        //f(10) = 432
        let result = eval_function(pars, 10i32.into());
        assert_eq!(Scalar::<Secp256k1>::from(432i32), result);
    }
}
