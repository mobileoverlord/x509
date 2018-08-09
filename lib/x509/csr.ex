defmodule X509.CSR do
  @moduledoc """
  Implements PKCS#10 Certificate Signing Requests (CSRs), formally known by
  their ASN.1 type CertificationRequest.

  For conversion to and from PEM or DER format, use the generic functions in
  the `X509` module.
  """

  import X509.ASN1

  alias X509.RDNSequence

  @typedoc """
  `:CertificationRequest` record , as used in Erlang's `:public_key` module
  """
  @opaque t :: X509.ASN1.record(:certification_request)

  # CertificationRequest record version
  @version :v1

  @doc """
  Returns a `:CertificationRequest` record for the given key pair and subject.

  Supports RSA and EC private keys. The public key is extracted from the
  private key and encoded, together with the subject, in the CSR. The CSR is
  then signed with the private key, using a configurable hash algorithm.

  The default hash algorithm is `:sha256`. An alternative algorithm can be
  specified using the `:hash` option. Possible values include `:sha224`,
  `:sha256`, `:sha384`, `:sha512`.

  Older hash algorithms, supported for compatibility with older software only,
  include `:md5` (RSA only) and `:sha`. The use of these algorithms is
  discouraged.
  """
  @spec new(X509.PrivateKey.t(), String.t() | X509.RDNSequence.t(), Keyword.t()) :: t()
  def new(private_key, subject, opts \\ []) do
    hash = Keyword.get(opts, :hash, :sha256)

    algorithm = sign_type(hash, private_key)

    # Convert subject to RDNSequence, if necessary
    subject_rdn_sequence =
      case subject do
        {:rdnSequence, _} -> subject
        rdn -> RDNSequence.new(rdn)
      end

    # CertificationRequestInfo to be signed
    info =
      certification_request_info(
        version: @version,
        subject: subject_rdn_sequence,
        subjectPKInfo:
          private_key
          |> X509.PublicKey.derive()
          |> X509.PublicKey.wrap(:CertificationRequestInfo_subjectPKInfo),
        attributes: []
      )

    info_der = :public_key.der_encode(:CertificationRequestInfo, info)
    signature = :public_key.sign(info_der, hash, private_key)

    certification_request(
      certificationRequestInfo: info,
      signatureAlgorithm: algorithm,
      signature: signature
    )
  end

  @doc """
  Extracts the public key from the CSR.
  """
  @spec public_key(t()) :: X509.PublicKey.t()
  def public_key(certification_request(certificationRequestInfo: info)) do
    info
    |> certification_request_info(:subjectPKInfo)
    |> X509.PublicKey.unwrap()
  end

  @doc """
  Returns the Subject field of the CSR.
  """
  @spec subject(t()) :: X509.RDNSequence.t()
  def subject(certification_request(certificationRequestInfo: info)) do
    info
    |> certification_request_info(:subject)
  end

  @doc """
  Verifies whether a CSR has a valid signature.
  """
  @spec valid?(t()) :: boolean()
  def valid?(
        certification_request(
          certificationRequestInfo: info,
          signatureAlgorithm: algorithm,
          signature: signature
        ) = csr
      ) do
    info_der = :public_key.der_encode(:CertificationRequestInfo, info)

    {digest_type, _} =
      algorithm
      |> certification_request_signature_algorithm(:algorithm)
      |> :public_key.pkix_sign_types()

    :public_key.verify(info_der, digest_type, signature, public_key(csr))
  end

  @doc """
  Converts a CSR to DER (binary) format.
  """
  @doc since: "0.3.0"
  @spec to_der(t()) :: binary()
  def to_der(certification_request() = csr) do
    :public_key.der_encode(:CertificationRequest, csr)
  end

  @doc """
  Converts a CSR to PEM format.
  """
  @doc since: "0.3.0"
  @spec to_pem(t()) :: String.t()
  def to_pem(certification_request() = csr) do
    :public_key.pem_entry_encode(:CertificationRequest, csr)
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  @doc """
  Attempts to parse a CSR in DER (binary) format. Raises in case of failure.
  """
  @doc since: "0.3.0"
  @spec from_der!(binary()) :: t() | no_return()
  def from_der!(der) do
    :public_key.der_decode(:CertificationRequest, der)
  end

  @doc """
  Parses a CSR in DER (binary) format.

  Returns an `:ok` tuple in case of success, or an `:error` tuple in case of
  failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a CSR
  """
  @doc since: "0.3.0"
  @spec from_der(binary()) :: {:ok, t()} | {:error, :malformed}
  def from_der(der) do
    {:ok, from_der!(der)}
  rescue
    MatchError -> {:error, :malformed}
  end

  @doc """
  Attempts to parse a CSR in PEM format. Raises in case of failure.

  Expects the input string to include exactly one PEM entry, which must be of
  type "CERTIFICATE REQUEST".
  """
  @doc since: "0.3.0"
  @spec from_pem!(String.t()) :: t() | no_return()
  def from_pem!(pem) do
    {:ok, csr} = from_pem(pem)
    csr
  end

  @doc """
  Parses a CSR in PEM format.

  Expects the input string to include exactly one PEM entry, which must be of
  type "CERTIFICATE REQUEST". Returns an `:ok` tuple in case of success, or an
  `:error` tuple in case of failure. Possible error reasons are:

    * `:malformed` - the data could not be decoded as a CSR
    * `:mismatch` - the PEM entry fround is of the wrong type
    * `:multiple` - the string provided contains multiple PEM entities

  *Note*: use `X509.from_pem/2` to decode and filter a string that may contain
  multiple PEM entities and get the results as a list, e.g.:

      csr_list = X509.from_pem(string, :CertificationRequest)
  """
  @doc since: "0.3.0"
  @spec from_pem(String.t()) :: {:ok, t()} | {:error, :malformed | :mismatch | :multiple}
  def from_pem(pem) do
    case :public_key.pem_decode(pem) do
      [{:CertificationRequest, der, :not_encrypted}] ->
        from_der(der)

      [_entry] ->
        {:error, :mismatch}

      _ ->
        {:error, :multiple}
    end
  end

  # Returns a :CertificationRequest_signatureAlgorithm record for the given
  # public key type and hash algorithm; this is essentially the reverse
  # of `:public_key.pkix_sign_types/1`
  defp sign_type(hash, rsa_private_key()) do
    sign_type(hash, :rsa)
  end

  defp sign_type(hash, ec_private_key()) do
    sign_type(hash, :ecdsa)
  end

  defp sign_type(:md5, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:md5WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:sha1WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha224, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:sha224WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha256, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:sha256WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha384, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:sha384WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(:sha512, :rsa) do
    certification_request_signature_algorithm(
      algorithm: oid(:sha512WithRSAEncryption),
      parameters: null()
    )
  end

  defp sign_type(hash, :rsa) do
    raise ArgumentError, "Unsupported hashing algorithm for RSA signing: #{inspect(hash)}"
  end

  defp sign_type(:sha, :ecdsa) do
    certification_request_signature_algorithm(algorithm: oid(:"ecdsa-with-SHA1"))
  end

  defp sign_type(:sha224, :ecdsa) do
    certification_request_signature_algorithm(algorithm: oid(:"ecdsa-with-SHA224"))
  end

  defp sign_type(:sha256, :ecdsa) do
    certification_request_signature_algorithm(algorithm: oid(:"ecdsa-with-SHA256"))
  end

  defp sign_type(:sha384, :ecdsa) do
    certification_request_signature_algorithm(algorithm: oid(:"ecdsa-with-SHA384"))
  end

  defp sign_type(:sha512, :ecdsa) do
    certification_request_signature_algorithm(algorithm: oid(:"ecdsa-with-SHA512"))
  end

  defp sign_type(hash, :ecdsa) do
    raise ArgumentError, "Unsupported hashing algorithm for ECDSA signing: #{inspect(hash)}"
  end
end
