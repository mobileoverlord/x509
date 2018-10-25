defmodule X509.Certificate.Template do
  @moduledoc """
  Certificate templates.
  """

  alias X509.Certificate.Extension

  import Extension
  import X509.ASN1, except: [extension: 2, basic_constraints: 2, basic_constraints: 1]
  alias X509.Certificate

  defstruct serial: {:random, 8}, validity: 365, hash: :sha256, extensions: []

  @type t :: %__MODULE__{
          serial: pos_integer() | {:random, pos_integer()},
          validity: pos_integer() | X509.Certificate.Validity.t(),
          hash: atom(),
          extensions: [{atom(), X509.Certificate.Extension.t() | boolean()}]
        }
  @type named_template :: :root_ca | :ca | :server

  @doc """
  Returns a template, optionally customized with user-provided validity, hash
  and extensions options.

  The base template can be selected from a list of built-in named templates,
  or as a custom template. The following named templates are supported:

    * `:root_ca` - intended for a self-signed root CA.

      The default path length constraint is set to 1, meaning the root CA can
      be used to issue intermediate CAs, and those CAs can only sign end
      certificates. The value can be overridden by passing a custom value
      for the `:basic_constraints` extension.

      The default validity is 25 years.

    * `:ca` - intended for intermediate CA certificates.

      The default path length constraint is set to 0, meaning the CA can only
      sign end certificates. The value can be overridden by passing a custom
      value for the `:basic_constraints` extension (assuming the issuing CA
      allows it).

      The Extended Key Usage extension is set to TLS server & client. Many
      (but not all) TLS implementations will interpret this as a constraint
      on the type of certificates the CA is allowed to issue. This constraint
      can be removed by setting `:ext_key_usage` to `false`, or by overriding
      the value to set the desired constraints.

      The default validity is 10 years.

    * `:server` - intended for end-certificates.

      The Extended Key Usage extension is set to TLS server & client. For other
      types of end-certificates, set the `:ext_key_usage` extension to the
      desired value. It may be necessary to update the `:key_usage` value as
      well.

      The default validity is 1 year, plus a 30 day grace period.

  All of the above templates generate a random 8 byte (64 bit) serial number,
  which can be overriden through the `:serial` option (see below).

  The `extensions` attribute of a template is a keyword list of extension
  name/value pairs, where the value should typically be an
  `X509.Certificate.Extension` record. The `subject_key_identifier` and
  `authority_key_identifier` extensions may simply be set to `true`: the
  actual values will be calculated during the certificate signing process.

  ## Options:

    * `:hash` - the hash algorithm to use when signing the certificate
    * `:serial` - the serial number of the certificate (an integer >0) or
      `{:random, n}` to generate an n-byte random serial number
    * `:validity` - override the validity period; can be specified as the
      number of days (integer) or a `X509.Certificate.Validity` value
    * `:extensions` - a keyword list of extensions to be merged into the
      template's defaults; set an extension value to `false` to exclude that
      extension from the certificate

  ## Examples:

      iex> X509.Certificate.Template.new(:root_ca,
      ...>   hash: :sha512, serial: 1,
      ...>   extensions: [authority_key_identifier: false]
      ...> )
      %X509.Certificate.Template{
        extensions: [
          basic_constraints: {:Extension, {2, 5, 29, 19}, true,
           {:BasicConstraints, true, 1}},
          key_usage: {:Extension, {2, 5, 29, 15}, true,
           [:digitalSignature, :keyCertSign, :cRLSign]},
          subject_key_identifier: true,
          authority_key_identifier: false
        ],
        hash: :sha512,
        serial: 1,
        validity: 9131
      }

      iex> X509.Certificate.Template.new(:server, extensions: [
      ...>   ext_key_usage: X509.Certificate.Extension.ext_key_usage([:codeSigning])
      ...> ])
      %X509.Certificate.Template{
        extensions: [
          basic_constraints: {:Extension, {2, 5, 29, 19}, false,
           {:BasicConstraints, false, :asn1_NOVALUE}},
          key_usage: {:Extension, {2, 5, 29, 15}, true,
           [:digitalSignature, :keyEncipherment]},
          subject_key_identifier: true,
          authority_key_identifier: true,
          ext_key_usage: {:Extension, {2, 5, 29, 37}, false,
           [{1, 3, 6, 1, 5, 5, 7, 3, 3}]}
        ],
        hash: :sha256,
        serial: {:random, 8},
        validity: 395
      }

  """
  @spec new(named_template() | t(), Keyword.t()) :: t()
  def new(template, opts \\ [])

  def new(:root_ca, opts) do
    %__MODULE__{
      # 25 years
      validity: round(25 * 365.2425),
      hash: :sha256,
      extensions: [
        basic_constraints: basic_constraints(true, 1),
        key_usage: key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
        subject_key_identifier: true,
        authority_key_identifier: true
      ]
    }
    |> new(opts)
  end

  def new(:ca, opts) do
    %__MODULE__{
      # 10 years
      validity: round(10 * 365.2425),
      hash: :sha256,
      extensions: [
        basic_constraints: basic_constraints(true, 0),
        key_usage: key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
        ext_key_usage: ext_key_usage([:serverAuth, :clientAuth]),
        subject_key_identifier: true,
        authority_key_identifier: true
      ]
    }
    |> new(opts)
  end

  def new(:server, opts) do
    %__MODULE__{
      # 1 year, plus a 30 days grace period
      validity: 365 + 30,
      hash: :sha256,
      extensions: [
        basic_constraints: basic_constraints(false),
        key_usage: key_usage([:digitalSignature, :keyEncipherment]),
        ext_key_usage: ext_key_usage([:serverAuth, :clientAuth]),
        subject_key_identifier: true,
        authority_key_identifier: true
      ]
    }
    |> new(opts)
  end

  def new(template, opts) do
    override =
      opts
      |> Keyword.take([:hash, :serial, :validity])
      |> Enum.into(%{})

    extensions =
      template.extensions
      |> Keyword.merge(Keyword.get(opts, :extensions, []))

    template
    |> Map.merge(override)
    |> Map.put(:extensions, extensions)
  end

  # If the template includes the Subject Key Identifier extension, sets the
  # value based on the given public key value
  def update_ski(template, public_key) do
    Map.update!(template, :extensions, fn extentions ->
      Keyword.update(extentions, :subject_key_identifier, false, fn
        true -> Extension.subject_key_identifier(public_key)
        false -> false
      end)
    end)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the issuer's SKI value (for plain certificate)
  def update_aki(template, certificate() = issuer) do
    aki =
      case Certificate.extension(issuer, oid(:"id-ce-subjectKeyIdentifier")) do
        nil ->
          nil

        plain_ski ->
          # FIXME: avoid calls to undocumented functions in :public_key app
          plain_ski
          |> :pubkey_cert_records.transform(:decode)
          |> X509.ASN1.extension(:extnValue)
      end

    update_aki(template, aki)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the issuer's SKI value (for OTP certificate)
  def update_aki(template, otp_certificate() = issuer) do
    aki =
      case Certificate.extension(issuer, oid(:"id-ce-subjectKeyIdentifier")) do
        nil -> nil
        extension(extnValue: id) -> id
      end

    update_aki(template, aki)
  end

  # If the template includes the Authority Key Identifier extension, sets it to
  # the specified binary value
  def update_aki(template, aki) when is_binary(aki) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.update(extensions, :authority_key_identifier, false, fn
        true -> Extension.authority_key_identifier(aki)
        false -> false
      end)
    end)
  end

  # No Authority Key Identifier value is available; disables the extension in
  # the template
  def update_aki(template, nil) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.put(extensions, :authority_key_identifier, false)
    end)
  end

  # If the template includes the Authority Key Identifier extension, sets the
  # value based on the given public key value
  def update_aki(template, public_key) do
    Map.update!(template, :extensions, fn extensions ->
      Keyword.update(extensions, :authority_key_identifier, false, fn
        true -> Extension.authority_key_identifier(public_key)
        false -> false
      end)
    end)
  end
end
