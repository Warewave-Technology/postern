import { useEffect, useState } from "react";

// Liste + hata + yenileme üçlüsü her sayfada aynı; tek kancada topla.
export function useList<T>(load: () => Promise<T[]>) {
  const [items, setItems] = useState<T[]>([]);
  const [error, setError] = useState("");
  const refresh = () => load().then(setItems).catch((e) => setError(String(e.message ?? e)));
  useEffect(() => { refresh(); }, []);
  return { items, error, refresh, setError };
}

export function ErrorLine({ msg }: { msg: string }) {
  return msg ? <p style={{ color: "crimson" }}>{msg}</p> : null;
}

export const th: React.CSSProperties = { textAlign: "left", borderBottom: "1px solid #ccc", padding: "0.3rem 0.6rem" };
export const td: React.CSSProperties = { padding: "0.3rem 0.6rem", borderBottom: "1px solid #eee" };
