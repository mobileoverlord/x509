defmodule X509.Certificate do
  @moduledoc """
  Module for issuing and working with X.509 certificates.

  For conversion to and from PEM or DER format, use the generic functions in
  the `X509` module.
  """

  import X509.ASN1, except: [extension: 2]

  alias X509.{PublicKey, RDNSequence}
  alias X509.Certificate.{Template, Validity, Extension}

  @typedoc """
  `:Certificate` record , as used in Erlang's `:public_key` module
  """
  @opaque t :: X509.ASN1.record(:otp_certificate)

  @version :v3

  @doc """
  Issues a new certificate.

  The public key can be an RSA key or an EC key (which results in an ECDSA
  certificate).

  The Subject can be specified as a string, to be parsed by
  `X509.RDNSequence.new/1`, or a custom RDN sequence tuple.

  The next parameters are the issuing certificate and the associated private
  key (RSA or EC). The Issuer field of the new certificate is taken from the
  issuing certificate's Subject.

  ## Options:

  * `:template` - an `X509.Certificate.Template` struct, or an atom selecting
    a built-in template (default: `:server`)
  * `:hash` - the hashing algorithm to use when signing the certificate
    (default: from template)
  * `:serial` - the certificate's serial number (default: from template, where
    it will typically be set to `nil`, resulting in a random value)
  * `:validity` - an integer specifying the certificate's validity in days,
    or an `X509.Certificate.Validity` record defining the 'not before' and
    'not after' timestamps (default: from template)
  * `:extensions` - a keyword list of extension names and values, to be merged
    with the extensions defined in the template; refer to the
    `X509.Certificate.Template` documentation for details
  """
  @spec new(
          X509.PublicKey.t(),
          String.t() | X509.RDNSequence.t(),
          t(),
          X509.PrivateKey.t(),
          Keyword.t()
        ) :: t()
  def new(public_key, subject_rdn, issuer, issuer_key, opts \\ []) do
    template =
      opts
      |> Keyword.get(:template, :server)
      |> Template.new(opts)
      |> update_ski(public_key)
      |> update_aki(issuer)

    algorithm =
      template
      |> Map.get(:hash)
      |> sign_type(issuer_key)

    issuer_rdn =
      case issuer do
        certificate(tbsCertificate: tbs) ->
          tbs
          |> otp_tbs_certificate(:issuer)
          |> :pubkey_cert_records.transform(:decode)

        otp_certificate(tbsCertificate: tbs) ->
          otp_tbs_certificate(tbs, :issuer)
      end

    public_key
    |> new_otp_tbs_certificate(subject_rdn, issuer_rdn, algorithm, template)
    |> :public_key.pkix_sign(issuer_key)
    |> from_der!()
  end

  @doc """
  Generates a new self-signed certificate.

  The private key is used both to sign and to extract the public key to be
  embedded in the certificate. It can be an RSA key or an EC key (which results
  in an ECDSA certificate).

  The Subject can be specified as a string, to be parsed by
  `X509.RDNSequence.new/1`, or a custom RDN sequence tuple. The same value is
  used in the Issuer field as well.

  ## Options:

  * `:template` - an `X509.Certificate.Template` struct, or an atom selecting
    a built-in template (default: `:server`)
  * `:hash` - the hashing algorithm to use when signing the certificate
    (default: from template)
  * `:serial` - the certificate's serial number (default: from template, where
    it will typically be set to `nil`, resulting in a random value)
  * `:validity` - an integer specifying the certificate's validity in days,
    or an `X509.Certificate.Validity` record defining the 'not before' and
    'not after' timestamps (default: from template)
  * `:extensions` - a keyword list of extension names and values, to be merged
    with the extensions defined in the template; refer to the
    `X509.Certificate.Template` documentation for details
  """
  @spec self_signed(
          X509.PrivateKey.t(),
          String.t() | X509.RDNSequence.t(),
          Keyword.t()
        ) :: t()
  def self_signed(private_key, subject_rdn, opts \\ []) do
    public_key = PublicKey.derive(private_key)

    template =
      opts
      |> Keyword.get(:template, :server)
      |> Template.new(opts)
      |> update_ski(public_key)
      |> update_aki(public_key)

    algorithm =
      template
      |> Map.get(:hash)
      |> sign_type(private_key)

    public_key
    |> new_otp_tbs_certificate(subject_rdn, subject_rdn, algorithm, template)
    |> :public_key.pkix_sign(private_key)
    |> from_der!()
  end

  @doc """
  Returns the Subject field of a certificate.
  """
  @spec subject(t()) :: X509.RDNSequence.t()
  def subject(certificate(tbsCertificate: tbs)) do
    tbs_certificate(tbs, :subject)
  end

  def subject(otp_certificate(tbsCertificate: tbs)) do
    otp_tbs_certificate(tbs, :subject)
  end

  @doc """
  Returns the Issuer field of a certificate.
  """
  @spec issuer(t()) :: X509.RDNSequence.t()
  def issuer(certificate(tbsCertificate: tbs)) do
    tbs_certificate(tbs, :issuer)
  end

  def issuer(otp_certificate(tbsCertificate: tbs)) do
    otp_tbs_certificate(tbs, :issuer)
  end

  @doc """
  Returns the Validity of a certificate.
  """
  @spec validity(t()) :: X509.Certificate.Validity.t()
  def validity(certificate(tbsCertificate: tbs)) do
    tbs_certificate(tbs, :validity)
  end

  def validity(otp_certificate(tbsCertificate: tbs)) do
    otp_tbs_certificate(tbs, :validity)
  end

  @doc """
  Returns the public key embedded in a certificate.
  """
  @spec public_key(t()) :: X509.PublicKey.t()
  def public_key(certificate(tbsCertificate: tbs)) do
    tbs
    |> tbs_certificate(:subjectPublicKeyInfo)
    |> PublicKey.unwrap()
  end

  def public_key(otp_certificate(tbsCertificate: tbs)) do
    tbs
    |> otp_tbs_certificate(:subjectPublicKeyInfo)
    |> PublicKey.unwrap()
  end

  @doc """
  Returns the list of extensions included in a certificate.
  """
  @spec extensions(t()) :: [X509.Certificate.Extension.t()]
  def extensions(certificate(tbsCertificate: tbs)) do
    tbs_certificate(tbs, :extensions)
  end

  def extensions(otp_certificate(tbsCertificate: tbs)) do
    otp_tbs_certificate(tbs, :extensions)
  end

  @doc """
  Looks up the value of a specific extension in a certificate.

  The desired extension can be specified as an atom or an OID value. Returns
  `nil` if the specified extension is not present in the certificate.
  """
  @spec extension(t(), X509.Certificate.Extension.extension_id() | :public_key.oid()) ::
          X509.Certificate.Extension.t() | nil
  def extension(cert, extension_id) do
    cert
    |> extensions()
    |> Extension.find(extension_id)
  end

  @doc """
  Converts a certificate to DER (binary) format.
  """
  @spec to_der(t()) :: binary()
  def to_der(otp_certificate() = certificate) do
    :public_key.pkix_encode(:OTPCertificate, certificate, :otp)
  end

  def to_der(certificate() = certificate) do
    :public_key.pkix_encode(:Certificate, certificate, :plain)
  end

  @doc """
  Converts a certificate to PEM format.
  """
  @spec to_pem(t()) :: String.t()
  def to_pem(certificate) do
    {:Certificate, to_der(certificate), :not_encrypted}
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Attempts to parse a certificate in DER (binary) format. Raises in case of failure.

  The optional second parameter specifies the record type to be returned:
  `:OTPCertificate` (default) or `:Certificate`.
  """
  # @doc since: "0.3.0"
  @spec from_der!(binary(), OTPCertificate | Certificate) :: t() | no_return()
  def from_der!(der, type \\ :OTPCertificate)

  def from_der!(der, :OTPCertificate) do
    :public_key.pkix_decode_cert(der, :otp)
  end

  def from_der!(der, :Certificate) do
    :public_key.pkix_decode_cert(der, :plain)
  end

  @doc """
  Attempts to parse a certificate in DER (binary) format.

  The optional second parameter specifies the record type to be returned:
  `:OTPCertificate` (default) or `:Certificate`.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a certificate
  """
  @spec from_der(binary(), :OTPCertificate | :Certificate) :: {:ok, t()} | {:error, :malformed}
  def from_der(der, type \\ :OTPCertificate) do
    {:ok, from_der!(der, type)}
  rescue
    MatchError -> {:error, :malformed}
  end

  @doc """
  Attempts to parse a certificate in PEM format. Raises in case of failure.

  Processes the first PEM entry of type CERTIFICATE found in the input. The
  optional second parameter specifies the record type to be returned:
  `:OTPCertificate` (default) or `:Certificate`.
  """
  @spec from_pem!(String.t(), :OTPCertificate | :Certificate) :: t() | no_return()
  def from_pem!(pem, type \\ :OTPCertificate) do
    {:ok, result} = from_pem(pem, type)
    result
  end

  @doc """
  Attempts to parse a certificate in PEM format.

  Processes the first PEM entry of type CERTIFICATE found in the input. The
  optional second parameter specifies the record type to be returned:
  `:OTPCertificate` (default) or `:Certificate`.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:not_found` - no PEM entry of type CERTIFICATE was found
    * `:malformed` - the entry could not be decoded as a certificate
  """
  @spec from_pem(String.t(), :OTPCertificate | :Certificate) ::
          {:ok, t()} | {:error, :malformed | :not_found}
  def from_pem(pem, type \\ :OTPCertificate) do
    pem
    |> :public_key.pem_decode()
    |> Enum.find(&match?({:Certificate, _, :not_encrypted}, &1))
    |> case do
      nil -> {:error, :not_found}
      {:Certificate, der, :not_encrypted} -> from_der(der, type)
    end
  end

  #
  # Helpers
  #

  defp new_otp_tbs_certificate(public_key, subject_rdn, issuer_rdn, algorithm, template) do
    otp_tbs_certificate(
      version: @version,
      serialNumber: Map.get(template, :serial) || random_serial(8),
      signature: algorithm,
      issuer:
        case issuer_rdn do
          {:rdnSequence, _} -> issuer_rdn
          name when is_binary(name) -> RDNSequence.new(name, :otp)
        end,
      validity:
        case template.validity do
          validity() = val -> val
          days -> Validity.days_from_now(days)
        end,
      subject:
        case subject_rdn do
          {:rdnSequence, _} -> subject_rdn
          name when is_binary(name) -> RDNSequence.new(name, :otp)
        end,
      subjectPublicKeyInfo: PublicKey.wrap(public_key, :OTPSubjectPublicKeyInfo),
      extensions:
        template.extensions
        |> Keyword.values()
        |> Enum.reject(&(&1 == false))
    )
  end

  # If the template includes the Subject Key Identifier extension, sets the
  # value based on the given public key value
  defp update_ski(template, public_key) do
    Map.update!(template, :extensions, fn extentions ->
      Keyword.update(extentions, :subject_key_identifier, false, fn
        true -> Extension.subject_key_identifier(public_key)
        false -> false
      end)
    end)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the issuer's SKI value (for plain certificate)
  defp update_aki(template, certificate() = issuer) do
    aki =
      case extension(issuer, oid(:"id-ce-subjectKeyIdentifier")) do
        nil ->
          nil

        plain_ski ->
          plain_ski
          |> :pubkey_cert_records.transform(:decode)
          |> X509.ASN1.extension(:extnValue)
      end

    update_aki(template, aki)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the issuer's SKI value (for OTP certificate)
  defp update_aki(template, otp_certificate() = issuer) do
    aki =
      case extension(issuer, oid(:"id-ce-subjectKeyIdentifier")) do
        nil -> nil
        extension(extnValue: id) -> id
      end

    update_aki(template, aki)
  end

  # If the template includes the Authority Key Identifier extension, sets it to
  # the specified binary value
  defp update_aki(template, aki) when is_binary(aki) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.update(extensions, :authority_key_identifier, false, fn
        true -> Extension.authority_key_identifier(aki)
        false -> false
      end)
    end)
  end

  # No Authority Key Identifier value is available; disables the extension in
  # the template
  defp update_aki(template, nil) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.put(extensions, :authority_key_identifier, false)
    end)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the given public key value
  defp update_aki(template, public_key) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.update(extensions, :authority_key_identifier, false, fn
        true -> Extension.authority_key_identifier(public_key)
        false -> false
      end)
    end)
  end

  # Returns a random serial number as an integer
  defp random_serial(size) do
    <<i::unsigned-size(size)-unit(8)>> = :crypto.strong_rand_bytes(size)
    i
  end

  # Returns a :SignatureAlgorithm record for the given public key type and hash
  # algorithm; this is essentially the reverse of
  # `:public_key.pkix_sign_types/1`
  defp sign_type(hash, rsa_private_key()) do
    sign_type(hash, :rsa)
  end

  defp sign_type(hash, ec_private_key()) do
    sign_type(hash, :ecdsa)
  end

  defp sign_type(:md5, :rsa) do
    signature_algorithm(
      algorithm: oid(:md5WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha, :rsa) do
    signature_algorithm(
      algorithm: oid(:sha1WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha224, :rsa) do
    signature_algorithm(
      algorithm: oid(:sha224WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha256, :rsa) do
    signature_algorithm(
      algorithm: oid(:sha256WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha384, :rsa) do
    signature_algorithm(
      algorithm: oid(:sha384WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha512, :rsa) do
    signature_algorithm(
      algorithm: oid(:sha512WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(hash, :rsa) do
    raise ArgumentError, "Unsupported hashing algorithm for RSA signing: #{inspect(hash)}"
  end

  defp sign_type(:sha, :ecdsa) do
    signature_algorithm(algorithm: oid(:"ecdsa-with-SHA1"))
  end

  defp sign_type(:sha224, :ecdsa) do
    signature_algorithm(algorithm: oid(:"ecdsa-with-SHA224"))
  end

  defp sign_type(:sha256, :ecdsa) do
    signature_algorithm(algorithm: oid(:"ecdsa-with-SHA256"))
  end

  defp sign_type(:sha384, :ecdsa) do
    signature_algorithm(algorithm: oid(:"ecdsa-with-SHA384"))
  end

  defp sign_type(:sha512, :ecdsa) do
    signature_algorithm(algorithm: oid(:"ecdsa-with-SHA512"))
  end

  defp sign_type(hash, :ecdsa) do
    raise ArgumentError, "Unsupported hashing algorithm for ECDSA signing: #{inspect(hash)}"
  end
end
