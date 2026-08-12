import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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

describe("manual connection creation", () => {
  const readyState = {
    ...emptyState,
    profile: { id: "profile-1", display_name: "Alex", created_at: "2026-08-12T00:00:00Z" },
  };

  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "app_state") return readyState;
      if (command === "connection_records") return [];
      if (command === "create_connection_definition") return {
        id: "connection-1",
        name: "acme-mcp",
        transport: "streamable_http",
        command: null,
        args: [],
        url: "https://mcp.example.com/mcp",
        environment_keys: [],
        metadata: { source: "manual" },
      };
      throw new Error(`Unexpected invoke: ${command}`);
    });
  });

  afterEach(cleanup);

  it("lets a clean profile save a reviewed remote definition without credentials", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Alex's vault" });
    fireEvent.click(screen.getByRole("button", { name: /connections/i }));
    const add = await screen.findByRole("button", { name: /add connection manually/i });
    fireEvent.click(add);

    const dialog = await screen.findByRole("dialog", { name: /add a connection to this vault/i });
    fireEvent.change(screen.getByLabelText(/connection identifier/i), { target: { value: "acme-mcp" } });
    fireEvent.change(screen.getByLabelText(/remote mcp url/i), { target: { value: "https://mcp.example.com/mcp" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /i reviewed every value/i }));
    fireEvent.click(screen.getByRole("button", { name: /save encrypted definition/i }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("create_connection_definition", {
      name: "acme-mcp",
      transport: "streamable_http",
      command: null,
      args: [],
      url: "https://mcp.example.com/mcp",
    }));
    await waitFor(() => expect(dialog).not.toBeInTheDocument());
    expect(await screen.findByText(/saved as an encrypted connection definition/i)).toBeVisible();
  });

  it("keeps a rejected definition open with a visible error", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "app_state") return readyState;
      if (command === "connection_records") return [];
      if (command === "create_connection_definition") throw new Error("a connection with this name already exists");
      throw new Error(`Unexpected invoke: ${command}`);
    });
    render(<App />);
    await screen.findByRole("button", { name: "Alex's vault" });
    fireEvent.click(screen.getByRole("button", { name: /connections/i }));
    fireEvent.click(await screen.findByRole("button", { name: /add connection manually/i }));
    fireEvent.change(screen.getByLabelText(/connection identifier/i), { target: { value: "acme-mcp" } });
    fireEvent.change(screen.getByLabelText(/remote mcp url/i), { target: { value: "https://mcp.example.com/mcp" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /i reviewed every value/i }));
    fireEvent.click(screen.getByRole("button", { name: /save encrypted definition/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/already exists/i);
    expect(screen.getByRole("dialog", { name: /add a connection to this vault/i })).toBeVisible();
  });

  it("preserves stdio argument whitespace and empty arguments", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Alex's vault" });
    fireEvent.click(screen.getByRole("button", { name: /connections/i }));
    fireEvent.click(await screen.findByRole("button", { name: /add connection manually/i }));
    fireEvent.change(screen.getByLabelText(/connection identifier/i), { target: { value: "stdio-mcp" } });
    fireEvent.change(screen.getByLabelText(/transport/i), { target: { value: "stdio" } });
    fireEvent.change(screen.getByLabelText(/executable path or command/i), { target: { value: "/usr/local/bin/mcp" } });
    fireEvent.click(screen.getByRole("button", { name: /^add argument$/i }));
    fireEvent.change(screen.getByLabelText("Argument 1"), { target: { value: "  spaced value  " } });
    fireEvent.click(screen.getByRole("button", { name: /^add argument$/i }));
    fireEvent.click(screen.getByRole("checkbox", { name: /i reviewed every value/i }));
    fireEvent.click(screen.getByRole("button", { name: /save encrypted definition/i }));

    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("create_connection_definition", {
      name: "stdio-mcp",
      transport: "stdio",
      command: "/usr/local/bin/mcp",
      args: ["  spaced value  ", ""],
      url: null,
    }));
  });
});

describe("provider local cleanup recovery", () => {
  const connection = {
    id: "connection-cleanup",
    name: "cleanup-mcp",
    transport: "streamable_http",
    command: null,
    args: [],
    url: "https://mcp.example.com/mcp",
    environment_keys: [],
    metadata: { source: "manual" },
  };
  const grant = {
    id: "grant-cleanup",
    connection_id: connection.id,
    resource: connection.url,
    issuer: "https://issuer.example.com",
    scopes: ["read"],
    access_expires_at: null,
    status: "local_cleanup_pending",
    created_at: "2026-08-12T00:00:00Z",
    last_verified_at: "2026-08-12T00:10:00Z",
  };

  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "app_state") return {
        ...emptyState,
        profile: { id: "profile-1", display_name: "Alex", created_at: "2026-08-12T00:00:00Z" },
        connection_count: 1,
        provider_grants: [grant],
      };
      if (command === "connection_records") return [connection];
      if (command === "finalize_provider_cleanup") return { ...grant, status: "verified_revoked" };
      throw new Error(`Unexpected invoke: ${command}`);
    });
  });

  afterEach(cleanup);

  it("exposes and runs local-only cleanup after provider evidence is complete", async () => {
    render(<App />);
    await screen.findByRole("button", { name: "Alex's vault" });
    fireEvent.click(screen.getByRole("button", { name: /connections/i }));
    fireEvent.click(await screen.findByRole("button", { name: /finish local cleanup/i }));
    const dialog = await screen.findByRole("dialog", { name: /finish local cleanup/i });
    expect(invokeMock).not.toHaveBeenCalledWith("finalize_provider_cleanup", expect.anything());
    expect(dialog).toHaveTextContent(/performs no provider network request/i);
    fireEvent.click(screen.getByRole("checkbox", { name: /irreversibly deletes/i }));
    fireEvent.click(within(dialog).getByRole("button", { name: /finish local cleanup/i }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith("finalize_provider_cleanup", { grantId: grant.id }));
    expect(await screen.findByText(/local keychain credential references were deleted/i)).toBeVisible();
  });
});
