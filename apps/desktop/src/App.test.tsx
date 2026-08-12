import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const invokeMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...arguments_: unknown[]) => invokeMock(...arguments_),
}));

const emptyState = {
  profile: null,
  hosts: [],
  deployments: [],
  provider_grants: [],
  connection_count: 0,
  memory_count: 0,
  receipts: [],
  receipt_chain_valid: true,
  vault_path: "/tmp/disposable-cargo-vault.sqlite3",
};

describe("fresh-device onboarding", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "app_state") return emptyState;
      throw new Error(`Unexpected invoke: ${command}`);
    });
  });

  afterEach(cleanup);

  it("offers encrypted restore before a profile is created", async () => {
    render(<App />);

    const restore = await screen.findByRole("button", { name: /restore encrypted pack/i });
    expect(restore).toBeEnabled();
    expect(screen.getByRole("button", { name: /create new local profile/i })).toBeVisible();

    restore.focus();
    expect(restore).toHaveFocus();
    fireEvent.click(restore);

    const dialog = await screen.findByRole("dialog", { name: /unlock and choose the pack/i });
    expect(dialog).toBeVisible();
    expect(document.querySelector("main.onboarding")).toHaveAttribute("inert");
    expect(screen.getByLabelText(/pack passphrase/i)).toBeVisible();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(dialog).not.toBeInTheDocument());
    expect(restore).toHaveFocus();
    expect(document.querySelector("main.onboarding")).not.toHaveAttribute("inert");
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("app_state"));
  });
});
