#![allow(non_snake_case)]
// sm2 curve by sm2 crate
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// Secp256k1 elliptic curve utility functions (se: https://en.bitcoin.it/wiki/Secp256k1).
//
// In Cryptography utilities, we need to manipulate low level elliptic curve members as Point
// in order to perform operation on them. As the library secp256k1 expose only SecretKey and
// PublicKey, we extend those with simple codecs.
//
// The Secret Key codec: BigInt <> SecretKey
// The Public Key codec: Point <> SecretKey
//

use std::convert::TryFrom;

use sm2::elliptic_curve::group::ff::PrimeField;
use sm2::elliptic_curve::group::prime::PrimeCurveAffine;
use sm2::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use sm2::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

use generic_array::GenericArray;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::arithmetic::*;
use super::traits::*;
use crate::elliptic::curves::{Curve, DeserializationError, NotOnCurve, PointCoords};
use crate::BigInt;

lazy_static::lazy_static! {
    static ref GROUP_ORDER: BigInt = BigInt::from_hex(&GROUP_ORDER_HEX).unwrap();

    static ref GENERATOR: Sm2Point = Sm2Point {
        purpose: "generator",
        ge: AffinePoint::generator(),
    };
}

const GROUP_ORDER_HEX: &str = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"; // Sm2 curve

/// Sm2 curve implementation based on [sm2] library
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sm2 {}

pub type SK = Scalar;
pub type PK = AffinePoint;

#[derive(Clone, Debug)]
pub struct Sm2Scalar {
    #[allow(dead_code)]
    purpose: &'static str,
    /// Zeroizing<SK> wraps SK and zeroize it on drop
    ///
    /// `fe` might be None — special case for scalar being zero
    fe: zeroize::Zeroizing<SK>,
}
#[derive(Clone, Debug, Copy)]
pub struct Sm2Point {
    #[allow(dead_code)]
    purpose: &'static str,
    ge: PK,
}

type GE = Sm2Point;
type FE = Sm2Scalar;

impl Curve for Sm2 {
    type Point = GE;
    type Scalar = FE;

    const CURVE_NAME: &'static str = "sm2";
}

impl ECScalar for Sm2Scalar {
    type Underlying = SK;

    type ScalarLength = typenum::U32;

    fn random() -> Sm2Scalar {
        let mut rng = thread_rng();
        let scalar = loop {
            let mut bytes = FieldBytes::default();
            rng.fill(&mut bytes[..]);
            let element = Scalar::from_repr(bytes);
            if bool::from(element.is_some()) {
                break element.unwrap();
            }
        };
        Sm2Scalar {
            purpose: "random",
            fe: scalar.into(),
        }
    }

    fn zero() -> Sm2Scalar {
        Sm2Scalar {
            purpose: "zero",
            fe: Scalar::ZERO.into(),
        }
    }

    fn is_zero(&self) -> bool {
        bool::from(self.fe.is_zero())
    }

    fn from_bigint(n: &BigInt) -> Sm2Scalar {
        let curve_order = Sm2Scalar::group_order();
        let n_reduced = n
            .modulus(curve_order)
            .to_bytes_array::<32>()
            .expect("n mod curve_order must be equal or less than 32 bytes");
        
        let bytes = FieldBytes::from(n_reduced);
        let scalar = Scalar::from_repr(bytes);

        Sm2Scalar {
            purpose: "from_bigint",
            fe: scalar.unwrap().into(),
        }
    }

    fn to_bigint(&self) -> BigInt {
        BigInt::from_bytes(self.fe.to_bytes().as_slice())
    }

    fn serialize(&self) -> GenericArray<u8, Self::ScalarLength> {
        self.fe.to_bytes()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let bytes = <[u8; 32]>::try_from(bytes).or(Err(DeserializationError))?;
        let bytes = FieldBytes::from(bytes);
        let scalar = Scalar::from_repr(bytes);

        if bool::from(scalar.is_some()) {
            Ok(Sm2Scalar {
                purpose: "deserialize",
                fe: scalar.unwrap().into(),
            })
        } else {
            Err(DeserializationError)
        }
    }

    fn add(&self, other: &Self) -> Sm2Scalar {
        Sm2Scalar {
            purpose: "add",
            fe: (*self.fe + *other.fe).into(),
        }
    }

    fn mul(&self, other: &Self) -> Sm2Scalar {
        Sm2Scalar {
            purpose: "mul",
            fe: (*self.fe * *other.fe).into(),
        }
    }

    fn sub(&self, other: &Self) -> Sm2Scalar {
        Sm2Scalar {
            purpose: "sub",
            fe: (*self.fe - *other.fe).into(),
        }
    }

    fn neg(&self) -> Self {
        Sm2Scalar {
            purpose: "sub",
            // fe: (-&*self.fe).into(),
            fe: (self.fe.neg()).into(),
        }
    }

    fn invert(&self) -> Option<Sm2Scalar> {
        Some(Sm2Scalar {
            purpose: "invert",
            fe: Option::<SK>::from(self.fe.invert())?.into(),
        })
    }

    fn add_assign(&mut self, other: &Self) {
        self.purpose = "add_assign";
        *self.fe += &*other.fe
    }
    fn mul_assign(&mut self, other: &Self) {
        self.purpose = "mul_assign";
        *self.fe *= &*other.fe
    }
    fn sub_assign(&mut self, other: &Self) {
        self.purpose = "sub_assign";
        *self.fe -= &*other.fe
    }

    fn group_order() -> &'static BigInt {
        &GROUP_ORDER
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.fe
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.fe
    }

    fn from_underlying(u: Self::Underlying) -> Sm2Scalar {
        Sm2Scalar {
            purpose: "from_underlying",
            fe: Zeroizing::new(u),
        }
    }
}

impl PartialEq for Sm2Scalar {
    fn eq(&self, other: &Sm2Scalar) -> bool {
        self.fe == other.fe
    }
}

impl ECPoint for Sm2Point {
    type Scalar = Sm2Scalar;
    type Underlying = PK;

    type CompressedPointLength = typenum::U33;
    type UncompressedPointLength = typenum::U65;

    fn zero() -> Sm2Point {
        Sm2Point {
            purpose: "zero",
            ge: AffinePoint::identity(),
        }
    }

    fn is_zero(&self) -> bool {
        bool::from(self.ge.is_identity())
    }

    fn generator() -> &'static Sm2Point {
        &GENERATOR
    }

    fn base_point2() -> &'static Sm2Point {
        &GENERATOR
    }

    fn from_coords(x: &BigInt, y: &BigInt) -> Result<Sm2Point, NotOnCurve> {
        let x_arr = x.to_bytes_array::<32>().ok_or(NotOnCurve)?;
        let y_arr = y.to_bytes_array::<32>().ok_or(NotOnCurve)?;
        let ge = PK::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x_arr.into(),
            &y_arr.into(),
            false,
        ));

        if bool::from(ge.is_some()) {
            Ok(Sm2Point {
                purpose: "from_coords",
                ge: ge.unwrap(),
            })
        } else {
            Err(NotOnCurve)
        }
    }

    fn x_coord(&self) -> Option<BigInt> {
        let encoded = self.ge.to_encoded_point(false);
        let x = BigInt::from_bytes(encoded.x()?.as_slice());
        Some(x)
    }

    fn y_coord(&self) -> Option<BigInt> {
        let encoded = self.ge.to_encoded_point(false);
        let y = BigInt::from_bytes(encoded.y()?.as_slice());
        Some(y)
    }

    fn coords(&self) -> Option<PointCoords> {
        let encoded = self.ge.to_encoded_point(false);
        let x = BigInt::from_bytes(encoded.x()?.as_slice());
        let y = BigInt::from_bytes(encoded.y()?.as_slice());
        Some(PointCoords { x, y })
    }

    fn serialize_compressed(&self) -> GenericArray<u8, Self::CompressedPointLength> {
        if self.is_zero() {
            *GenericArray::from_slice(&[0u8; 33])
        } else {
            *GenericArray::from_slice(self.ge.to_encoded_point(true).as_ref())
        }
    }

    fn serialize_uncompressed(&self) -> GenericArray<u8, Self::UncompressedPointLength> {
        if self.is_zero() {
            *GenericArray::from_slice(&[0u8; 65])
        } else {
            *GenericArray::from_slice(self.ge.to_encoded_point(false).as_ref())
        }
    }

    fn deserialize(bytes: &[u8]) -> Result<Sm2Point, DeserializationError> {
        if bytes == [0; 33] || bytes == [0; 65] {
            Ok(Sm2Point {
                purpose: "from_bytes",
                ge: Self::zero().ge,
            })
        } else {
            let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| DeserializationError)?;
            let affine_point = AffinePoint::from_encoded_point(&encoded);

            Ok(Sm2Point {
                purpose: "from_bytes",
                ge: affine_point.unwrap(),
            })
        }
    }

    fn check_point_order_equals_group_order(&self) -> bool {
        // This curve has cofactor=1 => any nonzero point has order GROUP_ORDER
        !self.is_zero()
    }

    fn scalar_mul(&self, scalar: &Self::Scalar) -> Sm2Point {
        Sm2Point {
            purpose: "scalar_mul",
            ge: (self.ge * *scalar.fe).to_affine(),
        }
    }

    fn generator_mul(scalar: &Self::Scalar) -> Self {
        Sm2Point {
            purpose: "generator_mul",
            ge: Sm2Point::generator().scalar_mul(scalar).ge,
        }
    }

    fn add_point(&self, other: &Self) -> Self {
        Sm2Point {
            purpose: "add_point",
            ge: (ProjectivePoint::from(self.ge) + other.ge).to_affine(),
        }
    }

    fn sub_point(&self, other: &Self) -> Sm2Point {
        Sm2Point {
            purpose: "sub",
            ge: (ProjectivePoint::from(self.ge) - other.ge).to_affine(),
        }
    }

    fn neg_point(&self) -> Sm2Point {
        Sm2Point {
            purpose: "neg",
            ge: -self.ge,
        }
    }

    fn scalar_mul_assign(&mut self, scalar: &Self::Scalar) {
        self.purpose = "mul_assign";
        self.ge = (self.ge * *scalar.fe).to_affine()
    }

    fn underlying_ref(&self) -> &Self::Underlying {
        &self.ge
    }
    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.ge
    }
    fn from_underlying(ge: Self::Underlying) -> Sm2Point {
        Sm2Point {
            purpose: "from_underlying",
            ge,
        }
    }
}

impl PartialEq for Sm2Point {
    fn eq(&self, other: &Sm2Point) -> bool {
        self.underlying_ref() == other.underlying_ref()
    }
}

impl Zeroize for Sm2Point {
    fn zeroize(&mut self) {
        self.ge.zeroize()
    }
}