import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

/*
 * ⚠️ jsdom <dialog>'un showModal/close'unu UYGULAMIYOR.
 *
 * Ekleme formlarının hepsi modalda (admin/Modal.tsx) ve bu yama
 * olmadan o formları açan hiçbir test yazılamıyor — yazılamayan test,
 * yazılmayan testtir. Yama tek tek test dosyalarında kopyalanıyordu;
 * üçüncü kopyaya gerek yok, kurulumda bir kez duruyor.
 */
/*
 * ⚠️ DOM VARLIĞI KONTROL EDİLİYOR: kurulum dosyası node ortamındaki
 * testlerde de koşuyor ve orada HTMLDialogElement HİÇ TANIMLI DEĞİL —
 * dosya, testin kendisi çalışmadan ReferenceError ile düşüyordu.
 * Ölçüldü: sftp.real.test.ts (gerçek sftp-server'a bağlanan test) bu
 * yüzden hiç koşamıyordu.
 */
if (
  typeof HTMLDialogElement !== "undefined" &&
  !HTMLDialogElement.prototype.showModal
) {
  HTMLDialogElement.prototype.showModal = function () {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function () {
    this.open = false;
  };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
