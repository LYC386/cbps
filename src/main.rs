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

    // let ans = Scalar::<E>::from(100i32);
    // println!("{:?}", g * &ans);
    // println!("{:?}", &mg);
    // if g * &ans == mg {
    //     println!("yes");
    // }

    let kp = &k_scalar * pk;
    let c2 = mg + kp;

    println!("(c1, c2) = ({:?}, {:?})", c1, c2);
    ElgamalCipher { c1, c2 }
}

pub fn elgamal_dec<E: Curve>(ct: ElgamalCipher<E>, sk: Scalar<E>) -> Result<Scalar<E>, ()> {
    let m_xc1 = -sk * &ct.c1;
    let mg = &m_xc1 + ct.c2;
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

    let (pk, sk) = gen_key::<Secp256k1>();
    // let m = BigInt::sample(SECURITY_BITS);
    let m_scalar = Scalar::<Secp256k1>::from(103i32);
    let ct = elgamal_enc(&m_scalar, &pk);
    let r = elgamal_dec(ct, sk).unwrap();
    let big_r = r.to_bigint();
    println!("{}", big_r);
}
