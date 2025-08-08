class SignInfo {
  final List<String> warnings;
  final bool verified;
  final Digests digests;
  final List<String> schemes;
  final List<String> verifiedSchemes;
  final List<String> errors;
  final String issuer;
  final String algorithm;
  final String createDate;
  final String expireDate;
  final String baseData;
  final List<int> rawData;

  SignInfo({
    required this.warnings,
    required this.verified,
    required this.digests,
    required this.schemes,
    required this.verifiedSchemes,
    required this.errors,
    required this.issuer,
    required this.algorithm,
    required this.createDate,
    required this.expireDate,
    required this.baseData,
    required this.rawData,
  });

  factory SignInfo.fromMap(Map<String, dynamic> map) {
    return SignInfo(
      warnings: List<String>.from(map['warnings']),
      verified: map['verified'] ?? false,
      digests: Digests.fromMap(Map<String, String>.from(map['digests'])),
      schemes: List<String>.from(map['schemes']),
      verifiedSchemes: List<String>.from(map['verified_schemes']),
      errors: List<String>.from(map['errors']),
      issuer: map['issuer'] ?? "",
      algorithm: map['algorithm'] ?? "",
      createDate: map['create_date'] ?? "",
      expireDate: map['expire_date'] ?? "",
      baseData: map['base64_data'] ?? "",
      rawData: List<int>.from(map['rawData'] ?? []),
    );
  }
}

class Digests {
  final String sha1;
  final String sha384;
  final String crc32;
  final String sha256;
  final String sha512;
  final String md5;
  final String hash;

  Digests({
    required this.sha1,
    required this.sha384,
    required this.crc32,
    required this.sha256,
    required this.sha512,
    required this.md5,
    required this.hash,
  });

  factory Digests.fromMap(Map<String, String> map) {
    return Digests(
      sha1: map['SHA-1'] ?? "",
      sha384: map['SHA-384'] ?? "",
      crc32: map['CRC32'] ?? "",
      sha256: map['SHA-256'] ?? "",
      sha512: map['SHA-512'] ?? "",
      md5: map['MD5'] ?? "",
      hash: map['HASH'] ?? "",
    );
  }
}
