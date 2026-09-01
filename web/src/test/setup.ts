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
if (!HTMLDialogElement.prototype.showModal) {
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
