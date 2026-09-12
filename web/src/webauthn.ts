/*
 * WebAuthn — tarayıcı ile sunucu arasındaki biçim çevirileri.
 *
 * ⚠️ NEDEN AYRI BİR DOSYA: burada çizilen hiçbir şey yok, ama yapılan
 * işin tamamı sessizce yanlış olabilir. Sunucu meydan okumayı base64url
 * METİN olarak gönderiyor, tarayıcı ise ArrayBuffer istiyor; çeviri
 * yanlışsa hata "anahtarınız kabul edilmedi" diye görünür ve suçlu
 * doğrulayıcı sanılır. Saf fonksiyonlar olarak durunca ölçülebiliyorlar.
 */

/** Tarayıcı WebAuthn'ı destekliyor mu. */
export function supported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator?.credentials?.create === "function"
  );
}

/*
 * ⚠️ base64url, base64 DEĞİL. WebAuthn her yerde base64url kullanıyor
 * ("-" ve "_", dolgu yok). atob'a doğrudan vermek, içinde "-" geçen her
 * meydan okumada bozuk bayt üretirdi — ve meydan okumalar rastgele
 * olduğu için arıza zamanın bir kısmında ortaya çıkar, yani en kötü
 * türden: ara ara.
 */
export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  // ⚠️ Tampon AÇIKÇA ArrayBuffer: tarayıcı API'leri BufferSource
  // istiyor ve tür tanımı SharedArrayBuffer üzerinden gelen bir
  // Uint8Array'i kabul etmiyor.
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);

  return out;
}

export function bytesToB64url(b: ArrayBuffer): string {
  const bytes = new Uint8Array(b);
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);

  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type Descriptor = { type: string; id: string; transports?: string[] };

// toDescriptors, kimlik bilgisi listesini tarayıcı biçimine çevirir.
function toDescriptors(
  list: Descriptor[] | undefined,
): PublicKeyCredentialDescriptor[] {
  return (list ?? []).map((d) => ({
    type: "public-key" as const,
    id: b64urlToBytes(d.id),
    transports: d.transports as AuthenticatorTransport[] | undefined,
  }));
}

/** Sunucunun kayıt seçeneklerini tarayıcının beklediği hâle çevirir. */
export function toCreationOptions(
  json: any,
): PublicKeyCredentialCreationOptions {
  const p = json?.publicKey ?? json;

  return {
    ...p,
    challenge: b64urlToBytes(p.challenge),
    user: { ...p.user, id: b64urlToBytes(p.user.id) },
    excludeCredentials: toDescriptors(p.excludeCredentials),
  };
}

/** Sunucunun giriş seçeneklerini tarayıcının beklediği hâle çevirir. */
export function toRequestOptions(
  json: any,
): PublicKeyCredentialRequestOptions {
  const p = json?.publicKey ?? json;

  return {
    ...p,
    challenge: b64urlToBytes(p.challenge),
    allowCredentials: toDescriptors(p.allowCredentials),
  };
}

/*
 * attestationToJSON, kaydın sonucunu sunucunun ayrıştırdığı biçime
 * çevirir.
 *
 * ⚠️ ALAN ADLARI ŞARTNAMEDEN, BİZDEN DEĞİL. Sunucu tarafı
 * go-webauthn'ın ayrıştırıcısı ve o, şartnamedeki adları bekliyor;
 * "kısaltıp düzeltmek" cazip ama karşı taraf sessizce reddeder.
 */
export function attestationToJSON(c: PublicKeyCredential): unknown {
  const r = c.response as AuthenticatorAttestationResponse;

  return {
    id: c.id,
    rawId: bytesToB64url(c.rawId),
    type: c.type,
    response: {
      clientDataJSON: bytesToB64url(r.clientDataJSON),
      attestationObject: bytesToB64url(r.attestationObject),
    },
  };
}

/** assertionToJSON, girişin sonucunu sunucunun ayrıştırdığı biçime çevirir. */
export function assertionToJSON(c: PublicKeyCredential): unknown {
  const r = c.response as AuthenticatorAssertionResponse;

  return {
    id: c.id,
    rawId: bytesToB64url(c.rawId),
    type: c.type,
    response: {
      clientDataJSON: bytesToB64url(r.clientDataJSON),
      authenticatorData: bytesToB64url(r.authenticatorData),
      signature: bytesToB64url(r.signature),
      /*
       * ⚠️ userHandle BOŞ OLABİLİR ve o hâlde GÖNDERİLMEMELİ. Boş bir
       * dizgi göndermek, sunucuya "kullanıcı kimliği bu" demek olurdu;
       * yokluğu ile boşluğu ayırmak doğrulamanın kendi işi.
       */
      userHandle: r.userHandle ? bytesToB64url(r.userHandle) : undefined,
    },
  };
}
