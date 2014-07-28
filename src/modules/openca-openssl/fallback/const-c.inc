#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_7 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     GEN_DNS GEN_RID GEN_URI XKU_SGC */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'G':
    if (memEQ(name, "XKU_SGC", 7)) {
    /*                    ^       */
#ifdef XKU_SGC
      *iv_return = XKU_SGC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "GEN_RID", 7)) {
    /*                    ^       */
#ifdef GEN_RID
      *iv_return = GEN_RID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "GEN_DNS", 7)) {
    /*                    ^       */
#ifdef GEN_DNS
      *iv_return = GEN_DNS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "GEN_URI", 7)) {
    /*                    ^       */
#ifdef GEN_URI
      *iv_return = GEN_URI;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_8 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CTX_TEST GEN_X400 NS_SMIME */
  /* Offset 0 gives the best switch position.  */
  switch (name[0]) {
  case 'C':
    if (memEQ(name, "CTX_TEST", 8)) {
    /*               ^             */
#ifdef CTX_TEST
      *iv_return = CTX_TEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "GEN_X400", 8)) {
    /*               ^             */
#ifdef GEN_X400
      *iv_return = GEN_X400;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "NS_SMIME", 8)) {
    /*               ^             */
#ifdef NS_SMIME
      *iv_return = NS_SMIME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_9 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     EXFLAG_CA EXFLAG_SS EXFLAG_V1 GEN_EMAIL GEN_IPADD NS_SSL_CA XKU_SMIME */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'C':
    if (memEQ(name, "EXFLAG_CA", 9)) {
    /*                      ^       */
#ifdef EXFLAG_CA
      *iv_return = EXFLAG_CA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NS_SSL_CA", 9)) {
    /*                      ^       */
#ifdef NS_SSL_CA
      *iv_return = NS_SSL_CA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "GEN_IPADD", 9)) {
    /*                      ^       */
#ifdef GEN_IPADD
      *iv_return = GEN_IPADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "GEN_EMAIL", 9)) {
    /*                      ^       */
#ifdef GEN_EMAIL
      *iv_return = GEN_EMAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "XKU_SMIME", 9)) {
    /*                      ^       */
#ifdef XKU_SMIME
      *iv_return = XKU_SMIME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "EXFLAG_SS", 9)) {
    /*                      ^       */
#ifdef EXFLAG_SS
      *iv_return = EXFLAG_SS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "EXFLAG_V1", 9)) {
    /*                      ^       */
#ifdef EXFLAG_V1
      *iv_return = EXFLAG_V1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_11 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     GEN_DIRNAME KU_CRL_SIGN NS_SMIME_CA */
  /* Offset 0 gives the best switch position.  */
  switch (name[0]) {
  case 'G':
    if (memEQ(name, "GEN_DIRNAME", 11)) {
    /*               ^                 */
#ifdef GEN_DIRNAME
      *iv_return = GEN_DIRNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "KU_CRL_SIGN", 11)) {
    /*               ^                 */
#ifdef KU_CRL_SIGN
      *iv_return = KU_CRL_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "NS_SMIME_CA", 11)) {
    /*               ^                 */
#ifdef NS_SMIME_CA
      *iv_return = NS_SMIME_CA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_13 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     EXFLAG_KUSAGE EXFLAG_NSCERT GEN_OTHERNAME NS_OBJSIGN_CA NS_SSL_CLIENT
     NS_SSL_SERVER XKU_CODE_SIGN */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'E':
    if (memEQ(name, "NS_SSL_SERVER", 13)) {
    /*                       ^           */
#ifdef NS_SSL_SERVER
      *iv_return = NS_SSL_SERVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "NS_OBJSIGN_CA", 13)) {
    /*                       ^           */
#ifdef NS_OBJSIGN_CA
      *iv_return = NS_OBJSIGN_CA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "NS_SSL_CLIENT", 13)) {
    /*                       ^           */
#ifdef NS_SSL_CLIENT
      *iv_return = NS_SSL_CLIENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "GEN_OTHERNAME", 13)) {
    /*                       ^           */
#ifdef GEN_OTHERNAME
      *iv_return = GEN_OTHERNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "EXFLAG_NSCERT", 13)) {
    /*                       ^           */
#ifdef EXFLAG_NSCERT
      *iv_return = EXFLAG_NSCERT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "EXFLAG_KUSAGE", 13)) {
    /*                       ^           */
#ifdef EXFLAG_KUSAGE
      *iv_return = EXFLAG_KUSAGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "XKU_CODE_SIGN", 13)) {
    /*                       ^           */
#ifdef XKU_CODE_SIGN
      *iv_return = XKU_CODE_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_14 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     EXFLAG_INVALID EXFLAG_XKUSAGE XKU_SSL_CLIENT XKU_SSL_SERVER */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'E':
    if (memEQ(name, "XKU_SSL_SERVER", 14)) {
    /*                           ^        */
#ifdef XKU_SSL_SERVER
      *iv_return = XKU_SSL_SERVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "EXFLAG_XKUSAGE", 14)) {
    /*                           ^        */
#ifdef EXFLAG_XKUSAGE
      *iv_return = EXFLAG_XKUSAGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "EXFLAG_INVALID", 14)) {
    /*                           ^        */
#ifdef EXFLAG_INVALID
      *iv_return = EXFLAG_INVALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "XKU_SSL_CLIENT", 14)) {
    /*                           ^        */
#ifdef XKU_SSL_CLIENT
      *iv_return = XKU_SSL_CLIENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     KU_DECIPHER_ONLY KU_ENCIPHER_ONLY KU_KEY_AGREEMENT KU_KEY_CERT_SIGN
     X509_PURPOSE_ANY X509_PURPOSE_MAX X509_PURPOSE_MIN */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'A':
    if (memEQ(name, "X509_PURPOSE_ANY", 16)) {
    /*                            ^         */
#ifdef X509_PURPOSE_ANY
      *iv_return = X509_PURPOSE_ANY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "KU_KEY_AGREEMENT", 16)) {
    /*                            ^         */
#ifdef KU_KEY_AGREEMENT
      *iv_return = KU_KEY_AGREEMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "KU_KEY_CERT_SIGN", 16)) {
    /*                            ^         */
#ifdef KU_KEY_CERT_SIGN
      *iv_return = KU_KEY_CERT_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "X509_PURPOSE_MAX", 16)) {
    /*                            ^         */
#ifdef X509_PURPOSE_MAX
      *iv_return = X509_PURPOSE_MAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509_PURPOSE_MIN", 16)) {
    /*                            ^         */
#ifdef X509_PURPOSE_MIN
      *iv_return = X509_PURPOSE_MIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "KU_DECIPHER_ONLY", 16)) {
    /*                            ^         */
#ifdef KU_DECIPHER_ONLY
      *iv_return = KU_DECIPHER_ONLY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "KU_ENCIPHER_ONLY", 16)) {
    /*                            ^         */
#ifdef KU_ENCIPHER_ONLY
      *iv_return = KU_ENCIPHER_ONLY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     KU_NON_REPUDIATION X509V3_EXT_CTX_DEP X509V3_EXT_DYNAMIC */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'D':
    if (memEQ(name, "X509V3_EXT_CTX_DEP", 18)) {
    /*                              ^         */
#ifdef X509V3_EXT_CTX_DEP
      *iv_return = X509V3_EXT_CTX_DEP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "KU_NON_REPUDIATION", 18)) {
    /*                              ^         */
#ifdef KU_NON_REPUDIATION
      *iv_return = KU_NON_REPUDIATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "X509V3_EXT_DYNAMIC", 18)) {
    /*                              ^         */
#ifdef X509V3_EXT_DYNAMIC
      *iv_return = X509V3_EXT_DYNAMIC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     KU_KEY_ENCIPHERMENT X509V3_F_COPY_EMAIL X509V3_F_DO_EXT_I2D
     X509V3_F_V2I_EXT_KU X509V3_R_BAD_OBJECT */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'B':
    if (memEQ(name, "X509V3_R_BAD_OBJECT", 19)) {
    /*                             ^           */
#ifdef X509V3_R_BAD_OBJECT
      *iv_return = X509V3_R_BAD_OBJECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "X509V3_F_COPY_EMAIL", 19)) {
    /*                             ^           */
#ifdef X509V3_F_COPY_EMAIL
      *iv_return = X509V3_F_COPY_EMAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "KU_KEY_ENCIPHERMENT", 19)) {
    /*                             ^           */
#ifdef KU_KEY_ENCIPHERMENT
      *iv_return = KU_KEY_ENCIPHERMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "X509V3_F_DO_EXT_I2D", 19)) {
    /*                             ^           */
#ifdef X509V3_F_DO_EXT_I2D
      *iv_return = X509V3_F_DO_EXT_I2D;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "X509V3_F_V2I_EXT_KU", 19)) {
    /*                             ^           */
#ifdef X509V3_F_V2I_EXT_KU
      *iv_return = X509V3_F_V2I_EXT_KU;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     KU_DATA_ENCIPHERMENT KU_DIGITAL_SIGNATURE X509V3_EXT_MULTILINE
     X509V3_F_COPY_ISSUER X509V3_F_DO_EXT_CONF X509V3_F_R2I_CERTPOL
     X509_PURPOSE_DYNAMIC */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'C':
    if (memEQ(name, "X509V3_F_COPY_ISSUER", 20)) {
    /*                        ^                 */
#ifdef X509V3_F_COPY_ISSUER
      *iv_return = X509V3_F_COPY_ISSUER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "X509V3_F_DO_EXT_CONF", 20)) {
    /*                        ^                 */
#ifdef X509V3_F_DO_EXT_CONF
      *iv_return = X509V3_F_DO_EXT_CONF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "KU_DIGITAL_SIGNATURE", 20)) {
    /*                        ^                 */
#ifdef KU_DIGITAL_SIGNATURE
      *iv_return = KU_DIGITAL_SIGNATURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "KU_DATA_ENCIPHERMENT", 20)) {
    /*                        ^                 */
#ifdef KU_DATA_ENCIPHERMENT
      *iv_return = KU_DATA_ENCIPHERMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "X509_PURPOSE_DYNAMIC", 20)) {
    /*                        ^                 */
#ifdef X509_PURPOSE_DYNAMIC
      *iv_return = X509_PURPOSE_DYNAMIC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "X509V3_F_R2I_CERTPOL", 20)) {
    /*                        ^                 */
#ifdef X509V3_F_R2I_CERTPOL
      *iv_return = X509V3_F_R2I_CERTPOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "X509V3_EXT_MULTILINE", 20)) {
    /*                        ^                 */
#ifdef X509V3_EXT_MULTILINE
      *iv_return = X509V3_EXT_MULTILINE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_HEX_TO_STRING X509V3_F_STRING_TO_HEX X509V3_F_SXNET_ADD_ASC
     X509V3_R_MISSING_VALUE X509V3_R_NO_PUBLIC_KEY X509V3_R_USER_TOO_LONG */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'A':
    if (memEQ(name, "X509V3_F_SXNET_ADD_ASC", 22)) {
    /*                                  ^         */
#ifdef X509V3_F_SXNET_ADD_ASC
      *iv_return = X509V3_F_SXNET_ADD_ASC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "X509V3_F_STRING_TO_HEX", 22)) {
    /*                                  ^         */
#ifdef X509V3_F_STRING_TO_HEX
      *iv_return = X509V3_F_STRING_TO_HEX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "X509V3_F_HEX_TO_STRING", 22)) {
    /*                                  ^         */
#ifdef X509V3_F_HEX_TO_STRING
      *iv_return = X509V3_F_HEX_TO_STRING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "X509V3_R_NO_PUBLIC_KEY", 22)) {
    /*                                  ^         */
#ifdef X509V3_R_NO_PUBLIC_KEY
      *iv_return = X509V3_R_NO_PUBLIC_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_R_MISSING_VALUE", 22)) {
    /*                                  ^         */
#ifdef X509V3_R_MISSING_VALUE
      *iv_return = X509V3_R_MISSING_VALUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "X509V3_R_USER_TOO_LONG", 22)) {
    /*                                  ^         */
#ifdef X509V3_R_USER_TOO_LONG
      *iv_return = X509V3_R_USER_TOO_LONG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_NOTICE_SECTION X509V3_F_POLICY_SECTION X509V3_F_X509V3_EXT_ADD
     X509V3_F_X509V3_EXT_I2D X509V3_R_BAD_IP_ADDRESS X509V3_R_INVALID_NUMBER
     X509V3_R_INVALID_OPTION X509V3_R_INVALID_SYNTAX X509V3_R_UNKNOWN_OPTION
     X509_PURPOSE_SMIME_SIGN X509_PURPOSE_SSL_CLIENT X509_PURPOSE_SSL_SERVER */
  /* Offset 18 gives the best switch position.  */
  switch (name[18]) {
  case 'C':
    if (memEQ(name, "X509V3_F_NOTICE_SECTION", 23)) {
    /*                                 ^           */
#ifdef X509V3_F_NOTICE_SECTION
      *iv_return = X509V3_F_NOTICE_SECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509V3_F_POLICY_SECTION", 23)) {
    /*                                 ^           */
#ifdef X509V3_F_POLICY_SECTION
      *iv_return = X509V3_F_POLICY_SECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "X509V3_R_BAD_IP_ADDRESS", 23)) {
    /*                                 ^           */
#ifdef X509V3_R_BAD_IP_ADDRESS
      *iv_return = X509V3_R_BAD_IP_ADDRESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "X509_PURPOSE_SSL_SERVER", 23)) {
    /*                                 ^           */
#ifdef X509_PURPOSE_SSL_SERVER
      *iv_return = X509_PURPOSE_SSL_SERVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509_PURPOSE_SSL_CLIENT", 23)) {
    /*                                 ^           */
#ifdef X509_PURPOSE_SSL_CLIENT
      *iv_return = X509_PURPOSE_SSL_CLIENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "X509V3_R_INVALID_OPTION", 23)) {
    /*                                 ^           */
#ifdef X509V3_R_INVALID_OPTION
      *iv_return = X509V3_R_INVALID_OPTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509V3_R_UNKNOWN_OPTION", 23)) {
    /*                                 ^           */
#ifdef X509V3_R_UNKNOWN_OPTION
      *iv_return = X509V3_R_UNKNOWN_OPTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "X509V3_F_X509V3_EXT_ADD", 23)) {
    /*                                 ^           */
#ifdef X509V3_F_X509V3_EXT_ADD
      *iv_return = X509V3_F_X509V3_EXT_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509V3_F_X509V3_EXT_I2D", 23)) {
    /*                                 ^           */
#ifdef X509V3_F_X509V3_EXT_I2D
      *iv_return = X509V3_F_X509V3_EXT_I2D;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "X509V3_R_INVALID_NUMBER", 23)) {
    /*                                 ^           */
#ifdef X509V3_R_INVALID_NUMBER
      *iv_return = X509V3_R_INVALID_NUMBER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "X509V3_R_INVALID_SYNTAX", 23)) {
    /*                                 ^           */
#ifdef X509V3_R_INVALID_SYNTAX
      *iv_return = X509V3_R_INVALID_SYNTAX;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "X509_PURPOSE_SMIME_SIGN", 23)) {
    /*                                 ^           */
#ifdef X509_PURPOSE_SMIME_SIGN
      *iv_return = X509_PURPOSE_SMIME_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_S2I_S2I_SKEY_ID X509V3_F_X509V3_EXT_CONF X509V3_R_BN_DEC2BN_ERROR
     X509V3_R_INVALID_NUMBERS X509V3_R_INVALID_SECTION */
  /* Offset 23 gives the best switch position.  */
  switch (name[23]) {
  case 'D':
    if (memEQ(name, "X509V3_F_S2I_S2I_SKEY_ID", 24)) {
    /*                                      ^       */
#ifdef X509V3_F_S2I_S2I_SKEY_ID
      *iv_return = X509V3_F_S2I_S2I_SKEY_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "X509V3_F_X509V3_EXT_CONF", 24)) {
    /*                                      ^       */
#ifdef X509V3_F_X509V3_EXT_CONF
      *iv_return = X509V3_F_X509V3_EXT_CONF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "X509V3_R_INVALID_SECTION", 24)) {
    /*                                      ^       */
#ifdef X509V3_R_INVALID_SECTION
      *iv_return = X509V3_R_INVALID_SECTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "X509V3_R_BN_DEC2BN_ERROR", 24)) {
    /*                                      ^       */
#ifdef X509V3_R_BN_DEC2BN_ERROR
      *iv_return = X509V3_R_BN_DEC2BN_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "X509V3_R_INVALID_NUMBERS", 24)) {
    /*                                      ^       */
#ifdef X509V3_R_INVALID_NUMBERS
      *iv_return = X509V3_R_INVALID_NUMBERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_I2S_ASN1_INTEGER X509V3_F_S2I_ASN1_INTEGER
     X509V3_F_S2I_ASN1_SKEY_ID X509V3_F_SXNET_GET_ID_ASC
     X509V3_F_V2I_GENERAL_NAME X509V3_F_X509V3_ADD_VALUE
     X509V3_F_X509_PURPOSE_ADD X509_PURPOSE_DYNAMIC_NAME */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'C':
    if (memEQ(name, "X509_PURPOSE_DYNAMIC_NAME", 25)) {
    /*                                  ^            */
#ifdef X509_PURPOSE_DYNAMIC_NAME
      *iv_return = X509_PURPOSE_DYNAMIC_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "X509V3_F_SXNET_GET_ID_ASC", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_SXNET_GET_ID_ASC
      *iv_return = X509V3_F_SXNET_GET_ID_ASC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "X509V3_F_S2I_ASN1_SKEY_ID", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_S2I_ASN1_SKEY_ID
      *iv_return = X509V3_F_S2I_ASN1_SKEY_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_F_V2I_GENERAL_NAME", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_V2I_GENERAL_NAME
      *iv_return = X509V3_F_V2I_GENERAL_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "X509V3_F_I2S_ASN1_INTEGER", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_I2S_ASN1_INTEGER
      *iv_return = X509V3_F_I2S_ASN1_INTEGER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509V3_F_S2I_ASN1_INTEGER", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_S2I_ASN1_INTEGER
      *iv_return = X509V3_F_S2I_ASN1_INTEGER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "X509V3_F_X509_PURPOSE_ADD", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_X509_PURPOSE_ADD
      *iv_return = X509V3_F_X509_PURPOSE_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "X509V3_F_X509V3_ADD_VALUE", 25)) {
    /*                                  ^            */
#ifdef X509V3_F_X509V3_ADD_VALUE
      *iv_return = X509V3_F_X509V3_ADD_VALUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_26 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_V2I_GENERAL_NAMES X509V3_F_X509V3_PARSE_LIST
     X509V3_R_DUPLICATE_ZONE_ID X509V3_R_ILLEGAL_HEX_DIGIT
     X509V3_R_INVALID_NULL_NAME X509V3_R_NO_ISSUER_DETAILS
     X509V3_R_UNKNOWN_EXTENSION X509_PURPOSE_NS_SSL_SERVER
     X509_PURPOSE_SMIME_ENCRYPT */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'D':
    if (memEQ(name, "X509V3_R_NO_ISSUER_DETAILS", 26)) {
    /*                                  ^             */
#ifdef X509V3_R_NO_ISSUER_DETAILS
      *iv_return = X509V3_R_NO_ISSUER_DETAILS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "X509_PURPOSE_SMIME_ENCRYPT", 26)) {
    /*                                  ^             */
#ifdef X509_PURPOSE_SMIME_ENCRYPT
      *iv_return = X509_PURPOSE_SMIME_ENCRYPT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_F_V2I_GENERAL_NAMES", 26)) {
    /*                                  ^             */
#ifdef X509V3_F_V2I_GENERAL_NAMES
      *iv_return = X509V3_F_V2I_GENERAL_NAMES;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "X509V3_R_INVALID_NULL_NAME", 26)) {
    /*                                  ^             */
#ifdef X509V3_R_INVALID_NULL_NAME
      *iv_return = X509V3_R_INVALID_NULL_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "X509V3_F_X509V3_PARSE_LIST", 26)) {
    /*                                  ^             */
#ifdef X509V3_F_X509V3_PARSE_LIST
      *iv_return = X509V3_F_X509V3_PARSE_LIST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "X509V3_R_UNKNOWN_EXTENSION", 26)) {
    /*                                  ^             */
#ifdef X509V3_R_UNKNOWN_EXTENSION
      *iv_return = X509V3_R_UNKNOWN_EXTENSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "X509V3_R_ILLEGAL_HEX_DIGIT", 26)) {
    /*                                  ^             */
#ifdef X509V3_R_ILLEGAL_HEX_DIGIT
      *iv_return = X509V3_R_ILLEGAL_HEX_DIGIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Z':
    if (memEQ(name, "X509V3_R_DUPLICATE_ZONE_ID", 26)) {
    /*                                  ^             */
#ifdef X509V3_R_DUPLICATE_ZONE_ID
      *iv_return = X509V3_R_DUPLICATE_ZONE_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "X509_PURPOSE_NS_SSL_SERVER", 26)) {
    /*                                  ^             */
#ifdef X509_PURPOSE_NS_SSL_SERVER
      *iv_return = X509_PURPOSE_NS_SSL_SERVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_27 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_S2I_ASN1_IA5STRING X509V3_F_SXNET_ADD_ID_ULONG
     X509V3_F_SXNET_GET_ID_ULONG X509V3_R_ERROR_IN_EXTENSION
     X509V3_R_INVALID_NULL_VALUE X509V3_R_NO_CONFIG_DATABASE
     X509V3_R_NO_SUBJECT_DETAILS X509V3_R_UNSUPPORTED_OPTION */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'A':
    if (memEQ(name, "X509V3_F_SXNET_ADD_ID_ULONG", 27)) {
    /*                              ^                  */
#ifdef X509V3_F_SXNET_ADD_ID_ULONG
      *iv_return = X509V3_F_SXNET_ADD_ID_ULONG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "X509V3_R_INVALID_NULL_VALUE", 27)) {
    /*                              ^                  */
#ifdef X509V3_R_INVALID_NULL_VALUE
      *iv_return = X509V3_R_INVALID_NULL_VALUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "X509V3_R_NO_CONFIG_DATABASE", 27)) {
    /*                              ^                  */
#ifdef X509V3_R_NO_CONFIG_DATABASE
      *iv_return = X509V3_R_NO_CONFIG_DATABASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "X509V3_F_SXNET_GET_ID_ULONG", 27)) {
    /*                              ^                  */
#ifdef X509V3_F_SXNET_GET_ID_ULONG
      *iv_return = X509V3_F_SXNET_GET_ID_ULONG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "X509V3_R_ERROR_IN_EXTENSION", 27)) {
    /*                              ^                  */
#ifdef X509V3_R_ERROR_IN_EXTENSION
      *iv_return = X509V3_R_ERROR_IN_EXTENSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'J':
    if (memEQ(name, "X509V3_R_NO_SUBJECT_DETAILS", 27)) {
    /*                              ^                  */
#ifdef X509V3_R_NO_SUBJECT_DETAILS
      *iv_return = X509V3_R_NO_SUBJECT_DETAILS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "X509V3_F_S2I_ASN1_IA5STRING", 27)) {
    /*                              ^                  */
#ifdef X509V3_F_S2I_ASN1_IA5STRING
      *iv_return = X509V3_F_S2I_ASN1_IA5STRING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "X509V3_R_UNSUPPORTED_OPTION", 27)) {
    /*                              ^                  */
#ifdef X509V3_R_UNSUPPORTED_OPTION
      *iv_return = X509V3_R_UNSUPPORTED_OPTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_28 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_I2S_ASN1_ENUMERATED X509V3_F_V2I_ASN1_BIT_STRING
     X509V3_F_V2I_AUTHORITY_KEYID X509V3_R_EXTENSION_NOT_FOUND
     X509V3_R_ISSUER_DECODE_ERROR */
  /* Offset 23 gives the best switch position.  */
  switch (name[23]) {
  case 'E':
    if (memEQ(name, "X509V3_R_ISSUER_DECODE_ERROR", 28)) {
    /*                                      ^           */
#ifdef X509V3_R_ISSUER_DECODE_ERROR
      *iv_return = X509V3_R_ISSUER_DECODE_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "X509V3_R_EXTENSION_NOT_FOUND", 28)) {
    /*                                      ^           */
#ifdef X509V3_R_EXTENSION_NOT_FOUND
      *iv_return = X509V3_R_EXTENSION_NOT_FOUND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "X509V3_F_V2I_AUTHORITY_KEYID", 28)) {
    /*                                      ^           */
#ifdef X509V3_F_V2I_AUTHORITY_KEYID
      *iv_return = X509V3_F_V2I_AUTHORITY_KEYID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "X509V3_F_I2S_ASN1_ENUMERATED", 28)) {
    /*                                      ^           */
#ifdef X509V3_F_I2S_ASN1_ENUMERATED
      *iv_return = X509V3_F_I2S_ASN1_ENUMERATED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "X509V3_F_V2I_ASN1_BIT_STRING", 28)) {
    /*                                      ^           */
#ifdef X509V3_F_V2I_ASN1_BIT_STRING
      *iv_return = X509V3_F_V2I_ASN1_BIT_STRING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_29 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_SXNET_ADD_ID_INTEGER X509V3_F_V3_GENERIC_EXTENSION
     X509V3_F_X509V3_EXT_ADD_ALIAS X509V3_R_EXTENSION_NAME_ERROR
     X509V3_R_NO_POLICY_IDENTIFIER X509V3_R_ODD_NUMBER_OF_DIGITS */
  /* Offset 25 gives the best switch position.  */
  switch (name[25]) {
  case 'E':
    if (memEQ(name, "X509V3_F_SXNET_ADD_ID_INTEGER", 29)) {
    /*                                        ^          */
#ifdef X509V3_F_SXNET_ADD_ID_INTEGER
      *iv_return = X509V3_F_SXNET_ADD_ID_INTEGER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "X509V3_R_NO_POLICY_IDENTIFIER", 29)) {
    /*                                        ^          */
#ifdef X509V3_R_NO_POLICY_IDENTIFIER
      *iv_return = X509V3_R_NO_POLICY_IDENTIFIER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "X509V3_R_ODD_NUMBER_OF_DIGITS", 29)) {
    /*                                        ^          */
#ifdef X509V3_R_ODD_NUMBER_OF_DIGITS
      *iv_return = X509V3_R_ODD_NUMBER_OF_DIGITS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_F_X509V3_EXT_ADD_ALIAS", 29)) {
    /*                                        ^          */
#ifdef X509V3_F_X509V3_EXT_ADD_ALIAS
      *iv_return = X509V3_F_X509V3_EXT_ADD_ALIAS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "X509V3_R_EXTENSION_NAME_ERROR", 29)) {
    /*                                        ^          */
#ifdef X509V3_R_EXTENSION_NAME_ERROR
      *iv_return = X509V3_R_EXTENSION_NAME_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "X509V3_F_V3_GENERIC_EXTENSION", 29)) {
    /*                                        ^          */
#ifdef X509V3_F_V3_GENERIC_EXTENSION
      *iv_return = X509V3_F_V3_GENERIC_EXTENSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_30 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_S2I_ASN1_OCTET_STRING X509V3_F_V2I_BASIC_CONSTRAINTS
     X509V3_F_X509V3_GET_VALUE_BOOL X509V3_R_ERROR_CONVERTING_ZONE
     X509V3_R_EXTENSION_VALUE_ERROR X509V3_R_INVALID_NULL_ARGUMENT
     X509V3_R_NO_ISSUER_CERTIFICATE */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'A':
    if (memEQ(name, "X509V3_F_S2I_ASN1_OCTET_STRING", 30)) {
    /*                            ^                       */
#ifdef X509V3_F_S2I_ASN1_OCTET_STRING
      *iv_return = X509V3_F_S2I_ASN1_OCTET_STRING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "X509V3_F_V2I_BASIC_CONSTRAINTS", 30)) {
    /*                            ^                       */
#ifdef X509V3_F_V2I_BASIC_CONSTRAINTS
      *iv_return = X509V3_F_V2I_BASIC_CONSTRAINTS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_R_INVALID_NULL_ARGUMENT", 30)) {
    /*                            ^                       */
#ifdef X509V3_R_INVALID_NULL_ARGUMENT
      *iv_return = X509V3_R_INVALID_NULL_ARGUMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "X509V3_R_EXTENSION_VALUE_ERROR", 30)) {
    /*                            ^                       */
#ifdef X509V3_R_EXTENSION_VALUE_ERROR
      *iv_return = X509V3_R_EXTENSION_VALUE_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "X509V3_R_ERROR_CONVERTING_ZONE", 30)) {
    /*                            ^                       */
#ifdef X509V3_R_ERROR_CONVERTING_ZONE
      *iv_return = X509V3_R_ERROR_CONVERTING_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "X509V3_R_NO_ISSUER_CERTIFICATE", 30)) {
    /*                            ^                       */
#ifdef X509V3_R_NO_ISSUER_CERTIFICATE
      *iv_return = X509V3_R_NO_ISSUER_CERTIFICATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "X509V3_F_X509V3_GET_VALUE_BOOL", 30)) {
    /*                            ^                       */
#ifdef X509V3_F_X509V3_GET_VALUE_BOOL
      *iv_return = X509V3_F_X509V3_GET_VALUE_BOOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_31 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_V2I_ACCESS_DESCRIPTION X509V3_R_INVALID_BOOLEAN_STRING
     X509V3_R_UNKNOWN_EXTENSION_NAME */
  /* Offset 29 gives the best switch position.  */
  switch (name[29]) {
  case 'M':
    if (memEQ(name, "X509V3_R_UNKNOWN_EXTENSION_NAME", 31)) {
    /*                                            ^        */
#ifdef X509V3_R_UNKNOWN_EXTENSION_NAME
      *iv_return = X509V3_R_UNKNOWN_EXTENSION_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "X509V3_R_INVALID_BOOLEAN_STRING", 31)) {
    /*                                            ^        */
#ifdef X509V3_R_INVALID_BOOLEAN_STRING
      *iv_return = X509V3_R_INVALID_BOOLEAN_STRING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "X509V3_F_V2I_ACCESS_DESCRIPTION", 31)) {
    /*                                            ^        */
#ifdef X509V3_F_V2I_ACCESS_DESCRIPTION
      *iv_return = X509V3_F_V2I_ACCESS_DESCRIPTION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_34 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     X509V3_F_I2V_AUTHORITY_INFO_ACCESS X509V3_R_INVALID_OBJECT_IDENTIFIER
     X509V3_R_INVALID_POLICY_IDENTIFIER */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'I':
    if (memEQ(name, "X509V3_F_I2V_AUTHORITY_INFO_ACCESS", 34)) {
    /*                                  ^                     */
#ifdef X509V3_F_I2V_AUTHORITY_INFO_ACCESS
      *iv_return = X509V3_F_I2V_AUTHORITY_INFO_ACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'J':
    if (memEQ(name, "X509V3_R_INVALID_OBJECT_IDENTIFIER", 34)) {
    /*                                  ^                     */
#ifdef X509V3_R_INVALID_OBJECT_IDENTIFIER
      *iv_return = X509V3_R_INVALID_OBJECT_IDENTIFIER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "X509V3_R_INVALID_POLICY_IDENTIFIER", 34)) {
    /*                                  ^                     */
#ifdef X509V3_R_INVALID_POLICY_IDENTIFIER
      *iv_return = X509V3_R_INVALID_POLICY_IDENTIFIER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(CTX_TEST EXFLAG_BCONS EXFLAG_CA EXFLAG_INVALID EXFLAG_KUSAGE
	       EXFLAG_NSCERT EXFLAG_SET EXFLAG_SS EXFLAG_V1 EXFLAG_XKUSAGE
	       GEN_DIRNAME GEN_DNS GEN_EDIPARTY GEN_EMAIL GEN_IPADD
	       GEN_OTHERNAME GEN_RID GEN_URI GEN_X400 KU_CRL_SIGN
	       KU_DATA_ENCIPHERMENT KU_DECIPHER_ONLY KU_DIGITAL_SIGNATURE
	       KU_ENCIPHER_ONLY KU_KEY_AGREEMENT KU_KEY_CERT_SIGN
	       KU_KEY_ENCIPHERMENT KU_NON_REPUDIATION NS_OBJSIGN NS_OBJSIGN_CA
	       NS_SMIME NS_SMIME_CA NS_SSL_CA NS_SSL_CLIENT NS_SSL_SERVER
	       X509V3_EXT_CTX_DEP X509V3_EXT_DYNAMIC X509V3_EXT_MULTILINE
	       X509V3_F_COPY_EMAIL X509V3_F_COPY_ISSUER X509V3_F_DO_EXT_CONF
	       X509V3_F_DO_EXT_I2D X509V3_F_HEX_TO_STRING
	       X509V3_F_I2S_ASN1_ENUMERATED X509V3_F_I2S_ASN1_INTEGER
	       X509V3_F_I2V_AUTHORITY_INFO_ACCESS X509V3_F_NOTICE_SECTION
	       X509V3_F_NREF_NOS X509V3_F_POLICY_SECTION X509V3_F_R2I_CERTPOL
	       X509V3_F_S2I_ASN1_IA5STRING X509V3_F_S2I_ASN1_INTEGER
	       X509V3_F_S2I_ASN1_OCTET_STRING X509V3_F_S2I_ASN1_SKEY_ID
	       X509V3_F_S2I_S2I_SKEY_ID X509V3_F_STRING_TO_HEX
	       X509V3_F_SXNET_ADD_ASC X509V3_F_SXNET_ADD_ID_INTEGER
	       X509V3_F_SXNET_ADD_ID_ULONG X509V3_F_SXNET_GET_ID_ASC
	       X509V3_F_SXNET_GET_ID_ULONG X509V3_F_V2I_ACCESS_DESCRIPTION
	       X509V3_F_V2I_ASN1_BIT_STRING X509V3_F_V2I_AUTHORITY_KEYID
	       X509V3_F_V2I_BASIC_CONSTRAINTS X509V3_F_V2I_CRLD
	       X509V3_F_V2I_EXT_KU X509V3_F_V2I_GENERAL_NAME
	       X509V3_F_V2I_GENERAL_NAMES X509V3_F_V3_GENERIC_EXTENSION
	       X509V3_F_X509V3_ADD_VALUE X509V3_F_X509V3_EXT_ADD
	       X509V3_F_X509V3_EXT_ADD_ALIAS X509V3_F_X509V3_EXT_CONF
	       X509V3_F_X509V3_EXT_I2D X509V3_F_X509V3_GET_VALUE_BOOL
	       X509V3_F_X509V3_PARSE_LIST X509V3_F_X509_PURPOSE_ADD
	       X509V3_R_BAD_IP_ADDRESS X509V3_R_BAD_OBJECT
	       X509V3_R_BN_DEC2BN_ERROR X509V3_R_BN_TO_ASN1_INTEGER_ERROR
	       X509V3_R_DUPLICATE_ZONE_ID X509V3_R_ERROR_CONVERTING_ZONE
	       X509V3_R_ERROR_IN_EXTENSION X509V3_R_EXPECTED_A_SECTION_NAME
	       X509V3_R_EXTENSION_NAME_ERROR X509V3_R_EXTENSION_NOT_FOUND
	       X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
	       X509V3_R_EXTENSION_VALUE_ERROR X509V3_R_ILLEGAL_HEX_DIGIT
	       X509V3_R_INVALID_BOOLEAN_STRING
	       X509V3_R_INVALID_EXTENSION_STRING X509V3_R_INVALID_NAME
	       X509V3_R_INVALID_NULL_ARGUMENT X509V3_R_INVALID_NULL_NAME
	       X509V3_R_INVALID_NULL_VALUE X509V3_R_INVALID_NUMBER
	       X509V3_R_INVALID_NUMBERS X509V3_R_INVALID_OBJECT_IDENTIFIER
	       X509V3_R_INVALID_OPTION X509V3_R_INVALID_POLICY_IDENTIFIER
	       X509V3_R_INVALID_SECTION X509V3_R_INVALID_SYNTAX
	       X509V3_R_ISSUER_DECODE_ERROR X509V3_R_MISSING_VALUE
	       X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
	       X509V3_R_NO_CONFIG_DATABASE X509V3_R_NO_ISSUER_CERTIFICATE
	       X509V3_R_NO_ISSUER_DETAILS X509V3_R_NO_POLICY_IDENTIFIER
	       X509V3_R_NO_PUBLIC_KEY X509V3_R_NO_SUBJECT_DETAILS
	       X509V3_R_ODD_NUMBER_OF_DIGITS
	       X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
	       X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
	       X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT X509V3_R_UNKNOWN_EXTENSION
	       X509V3_R_UNKNOWN_EXTENSION_NAME X509V3_R_UNKNOWN_OPTION
	       X509V3_R_UNSUPPORTED_OPTION X509V3_R_USER_TOO_LONG
	       X509_PURPOSE_ANY X509_PURPOSE_CRL_SIGN X509_PURPOSE_DYNAMIC
	       X509_PURPOSE_DYNAMIC_NAME X509_PURPOSE_MAX X509_PURPOSE_MIN
	       X509_PURPOSE_NS_SSL_SERVER X509_PURPOSE_SMIME_ENCRYPT
	       X509_PURPOSE_SMIME_SIGN X509_PURPOSE_SSL_CLIENT
	       X509_PURPOSE_SSL_SERVER XKU_CODE_SIGN XKU_SGC XKU_SMIME
	       XKU_SSL_CLIENT XKU_SSL_SERVER));

print constant_types(); # macro defs
foreach (C_constant ("OpenCA::OpenSSL::Fast", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "#### XS Section:\n";
print XS_constant ("OpenCA::OpenSSL::Fast", $types);
__END__
   */

  switch (len) {
  case 7:
    return constant_7 (aTHX_ name, iv_return);
    break;
  case 8:
    return constant_8 (aTHX_ name, iv_return);
    break;
  case 9:
    return constant_9 (aTHX_ name, iv_return);
    break;
  case 10:
    /* Names all of length 10.  */
    /* EXFLAG_SET NS_OBJSIGN */
    /* Offset 4 gives the best switch position.  */
    switch (name[4]) {
    case 'A':
      if (memEQ(name, "EXFLAG_SET", 10)) {
      /*                   ^            */
#ifdef EXFLAG_SET
        *iv_return = EXFLAG_SET;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'B':
      if (memEQ(name, "NS_OBJSIGN", 10)) {
      /*                   ^            */
#ifdef NS_OBJSIGN
        *iv_return = NS_OBJSIGN;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 11:
    return constant_11 (aTHX_ name, iv_return);
    break;
  case 12:
    /* Names all of length 12.  */
    /* EXFLAG_BCONS GEN_EDIPARTY */
    /* Offset 0 gives the best switch position.  */
    switch (name[0]) {
    case 'E':
      if (memEQ(name, "EXFLAG_BCONS", 12)) {
      /*               ^                  */
#ifdef EXFLAG_BCONS
        *iv_return = EXFLAG_BCONS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'G':
      if (memEQ(name, "GEN_EDIPARTY", 12)) {
      /*               ^                  */
#ifdef GEN_EDIPARTY
        *iv_return = GEN_EDIPARTY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 13:
    return constant_13 (aTHX_ name, iv_return);
    break;
  case 14:
    return constant_14 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    /* Names all of length 17.  */
    /* X509V3_F_NREF_NOS X509V3_F_V2I_CRLD */
    /* Offset 15 gives the best switch position.  */
    switch (name[15]) {
    case 'L':
      if (memEQ(name, "X509V3_F_V2I_CRLD", 17)) {
      /*                              ^        */
#ifdef X509V3_F_V2I_CRLD
        *iv_return = X509V3_F_V2I_CRLD;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'O':
      if (memEQ(name, "X509V3_F_NREF_NOS", 17)) {
      /*                              ^        */
#ifdef X509V3_F_NREF_NOS
        *iv_return = X509V3_F_NREF_NOS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    /* Names all of length 21.  */
    /* X509V3_R_INVALID_NAME X509_PURPOSE_CRL_SIGN */
    /* Offset 10 gives the best switch position.  */
    switch (name[10]) {
    case 'N':
      if (memEQ(name, "X509V3_R_INVALID_NAME", 21)) {
      /*                         ^                 */
#ifdef X509V3_R_INVALID_NAME
        *iv_return = X509V3_R_INVALID_NAME;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'S':
      if (memEQ(name, "X509_PURPOSE_CRL_SIGN", 21)) {
      /*                         ^                 */
#ifdef X509_PURPOSE_CRL_SIGN
        *iv_return = X509_PURPOSE_CRL_SIGN;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    return constant_26 (aTHX_ name, iv_return);
    break;
  case 27:
    return constant_27 (aTHX_ name, iv_return);
    break;
  case 28:
    return constant_28 (aTHX_ name, iv_return);
    break;
  case 29:
    return constant_29 (aTHX_ name, iv_return);
    break;
  case 30:
    return constant_30 (aTHX_ name, iv_return);
    break;
  case 31:
    return constant_31 (aTHX_ name, iv_return);
    break;
  case 32:
    if (memEQ(name, "X509V3_R_EXPECTED_A_SECTION_NAME", 32)) {
#ifdef X509V3_R_EXPECTED_A_SECTION_NAME
      *iv_return = X509V3_R_EXPECTED_A_SECTION_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 33:
    /* Names all of length 33.  */
    /* X509V3_R_BN_TO_ASN1_INTEGER_ERROR X509V3_R_INVALID_EXTENSION_STRING */
    /* Offset 22 gives the best switch position.  */
    switch (name[22]) {
    case 'S':
      if (memEQ(name, "X509V3_R_INVALID_EXTENSION_STRING", 33)) {
      /*                                     ^                 */
#ifdef X509V3_R_INVALID_EXTENSION_STRING
        *iv_return = X509V3_R_INVALID_EXTENSION_STRING;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "X509V3_R_BN_TO_ASN1_INTEGER_ERROR", 33)) {
      /*                                     ^                 */
#ifdef X509V3_R_BN_TO_ASN1_INTEGER_ERROR
        *iv_return = X509V3_R_BN_TO_ASN1_INTEGER_ERROR;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 34:
    return constant_34 (aTHX_ name, iv_return);
    break;
  case 35:
    if (memEQ(name, "X509V3_R_UNABLE_TO_GET_ISSUER_KEYID", 35)) {
#ifdef X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
      *iv_return = X509V3_R_UNABLE_TO_GET_ISSUER_KEYID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 36:
    if (memEQ(name, "X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT", 36)) {
#ifdef X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT
      *iv_return = X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 37:
    if (memEQ(name, "X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS", 37)) {
#ifdef X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
      *iv_return = X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 38:
    if (memEQ(name, "X509V3_R_NEED_ORGANIZATION_AND_NUMBERS", 38)) {
#ifdef X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
      *iv_return = X509V3_R_NEED_ORGANIZATION_AND_NUMBERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 40:
    if (memEQ(name, "X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED", 40)) {
#ifdef X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
      *iv_return = X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

