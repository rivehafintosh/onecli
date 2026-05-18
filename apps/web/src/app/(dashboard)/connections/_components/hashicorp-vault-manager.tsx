"use client";

import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  Database,
  FileKey2,
  Folder,
  RefreshCw,
  Save,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@onecli/ui/components/badge";
import { Button } from "@onecli/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@onecli/ui/components/card";
import { Input } from "@onecli/ui/components/input";
import { Label } from "@onecli/ui/components/label";
import {
  browseHashicorpVaultPath,
  getHashicorpVaultMappings,
  getHashicorpVaultPathMetadata,
  removeHashicorpVaultMapping,
  saveHashicorpVaultMapping,
  writeHashicorpVaultFields,
} from "@/lib/actions/hashicorp-vault";

type VaultPathEntry = Awaited<
  ReturnType<typeof browseHashicorpVaultPath>
>[number];
type VaultMapping = Awaited<
  ReturnType<typeof getHashicorpVaultMappings>
>[number];

interface HashicorpVaultManagerProps {
  onChanged: () => Promise<void>;
}

export const HashicorpVaultManager = ({
  onChanged,
}: HashicorpVaultManagerProps) => {
  const [pathInput, setPathInput] = useState("");
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<VaultPathEntry[]>([]);
  const [mappings, setMappings] = useState<VaultMapping[]>([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [fields, setFields] = useState<string[]>([]);
  const [hostname, setHostname] = useState("");
  const [field, setField] = useState("");
  const [usernameField, setUsernameField] = useState("");
  const [writeField, setWriteField] = useState("");
  const [writeValue, setWriteValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [savingMapping, setSavingMapping] = useState(false);
  const [writing, setWriting] = useState(false);
  const browseRequestRef = useRef(0);

  const refreshMappings = useCallback(async () => {
    setMappings(await getHashicorpVaultMappings());
  }, []);

  const browse = useCallback(async (path: string, syncInput = true) => {
    const requestId = browseRequestRef.current + 1;
    browseRequestRef.current = requestId;
    const nextPath = path.trim().replace(/^\/+|\/+$/g, "");
    setLoading(true);
    try {
      const result = await browseHashicorpVaultPath(nextPath);
      if (browseRequestRef.current !== requestId) return;
      setEntries(result);
      setCurrentPath(nextPath);
      if (syncInput) setPathInput(nextPath);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to list Vault path",
      );
    } finally {
      if (browseRequestRef.current === requestId) setLoading(false);
    }
  }, []);

  const inspectPath = useCallback(async (path: string) => {
    setLoading(true);
    try {
      const metadata = await getHashicorpVaultPathMetadata(path);
      setSelectedPath(metadata.path);
      setFields(metadata.fields);
      setField(metadata.fields[0] ?? "");
      setWriteField(metadata.fields[0] ?? "");
      const firstMapping = metadata.mappings[0];
      setHostname(firstMapping?.hostname ?? "");
      setUsernameField(firstMapping?.username_field ?? "");
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Failed to read Vault metadata",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    browse("", false).catch(() => {});
    refreshMappings().catch(() => {});
  }, [browse, refreshMappings]);

  const handleEntryClick = async (entry: VaultPathEntry) => {
    if (entry.folder) {
      await browse(entry.path);
      return;
    }
    await inspectPath(entry.path);
  };

  const handleMappingSave = async () => {
    if (!selectedPath || !hostname.trim() || !field.trim()) return;
    setSavingMapping(true);
    try {
      setMappings(
        await saveHashicorpVaultMapping({
          hostname,
          path: selectedPath,
          field,
          usernameField: usernameField || undefined,
        }),
      );
      toast.success("Vault mapping saved");
      await onChanged();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to save mapping",
      );
    } finally {
      setSavingMapping(false);
    }
  };

  const handleMappingDelete = async (mapping: VaultMapping) => {
    try {
      setMappings(
        await removeHashicorpVaultMapping({
          hostname: mapping.hostname,
          path: mapping.path,
          field: mapping.field,
          usernameField: mapping.username_field,
        }),
      );
      toast.success("Vault mapping removed");
      await onChanged();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to remove mapping",
      );
    }
  };

  const handleWrite = async () => {
    if (!selectedPath || !writeField.trim() || !writeValue) return;
    setWriting(true);
    try {
      const metadata = await writeHashicorpVaultFields(selectedPath, {
        [writeField]: writeValue,
      });
      setFields(metadata.fields);
      setField(writeField);
      setWriteValue("");
      toast.success("Vault secret updated");
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : "Failed to update Vault secret",
      );
    } finally {
      setWriting(false);
    }
  };

  const handlePathSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await browse(pathInput);
  };

  const parentPath = currentPath.split("/").slice(0, -1).join("/");

  return (
    <Card>
      <CardHeader>
        <CardTitle>Vault Credentials</CardTitle>
        <CardDescription>
          Browse KV metadata, map fields to hostnames, and write new field
          values without exposing existing secret values.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(340px,0.9fr)]">
        <div className="space-y-3">
          <form className="flex gap-2" onSubmit={handlePathSubmit}>
            <Input
              value={pathInput}
              onChange={(event) => setPathInput(event.target.value)}
              placeholder="Vault path"
              className="font-mono text-sm"
            />
            <Button
              type="submit"
              variant="outline"
              size="icon"
              disabled={loading}
              aria-label="Browse Vault path"
            >
              <RefreshCw
                className={`size-4 ${loading ? "animate-spin" : ""}`}
              />
            </Button>
          </form>

          <div className="divide-border min-h-52 overflow-hidden rounded-md border">
            {currentPath && (
              <button
                type="button"
                onClick={() => browse(parentPath)}
                className="hover:bg-muted/50 flex w-full items-center gap-2 px-3 py-2 text-left text-sm"
              >
                <Folder className="text-muted-foreground size-4" />
                ..
              </button>
            )}
            {entries.map((entry) => (
              <button
                type="button"
                key={`${entry.path}:${entry.folder}`}
                onClick={() => handleEntryClick(entry)}
                className="hover:bg-muted/50 flex w-full items-center gap-2 border-t px-3 py-2 text-left text-sm first:border-t-0"
              >
                {entry.folder ? (
                  <Folder className="text-muted-foreground size-4" />
                ) : (
                  <FileKey2 className="text-muted-foreground size-4" />
                )}
                <span className="truncate font-mono text-xs">{entry.name}</span>
              </button>
            ))}
            {!loading && entries.length === 0 && (
              <p className="text-muted-foreground px-3 py-8 text-center text-xs">
                No entries found.
              </p>
            )}
            {loading && (
              <p className="text-muted-foreground px-3 py-8 text-center text-xs">
                Loading...
              </p>
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-md border p-3">
            <div className="mb-3 flex items-center justify-between gap-2">
              <div>
                <p className="text-sm font-medium">Selected secret</p>
                <code className="text-muted-foreground text-xs">
                  {selectedPath || "Choose a path"}
                </code>
              </div>
              {fields.length > 0 && (
                <Badge variant="secondary">{fields.length} fields</Badge>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {fields.map((item) => (
                <button
                  type="button"
                  key={item}
                  onClick={() => {
                    setField(item);
                    setWriteField(item);
                  }}
                  className="bg-muted hover:bg-muted/70 rounded px-2 py-1 font-mono text-xs"
                >
                  {item}
                </button>
              ))}
              {selectedPath && fields.length === 0 && (
                <p className="text-muted-foreground text-xs">
                  No fields found.
                </p>
              )}
            </div>
          </div>

          <div className="space-y-3 rounded-md border p-3">
            <div className="grid gap-2">
              <Label>Hostname</Label>
              <Input
                value={hostname}
                onChange={(event) => setHostname(event.target.value)}
                placeholder="api.openai.com"
                disabled={!selectedPath}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label>Secret field</Label>
                <Input
                  value={field}
                  onChange={(event) => setField(event.target.value)}
                  placeholder="api_key"
                  disabled={!selectedPath}
                />
              </div>
              <div className="grid gap-2">
                <Label>Username field</Label>
                <Input
                  value={usernameField}
                  onChange={(event) => setUsernameField(event.target.value)}
                  placeholder="username"
                  disabled={!selectedPath}
                />
              </div>
            </div>
            <Button
              size="sm"
              onClick={handleMappingSave}
              loading={savingMapping}
              disabled={!selectedPath || !hostname.trim() || !field.trim()}
            >
              <Save className="size-3.5" />
              {savingMapping ? "Saving..." : "Save mapping"}
            </Button>
          </div>

          <div className="space-y-3 rounded-md border p-3">
            <p className="text-sm font-medium">Create or update field</p>
            <div className="grid grid-cols-2 gap-3">
              <Input
                value={writeField}
                onChange={(event) => setWriteField(event.target.value)}
                placeholder="field"
                disabled={!selectedPath}
              />
              <Input
                value={writeValue}
                onChange={(event) => setWriteValue(event.target.value)}
                placeholder="new value"
                type="password"
                disabled={!selectedPath}
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={handleWrite}
              loading={writing}
              disabled={!selectedPath || !writeField.trim() || !writeValue}
            >
              <Database className="size-3.5" />
              {writing ? "Writing..." : "Write field"}
            </Button>
          </div>
        </div>

        <div className="space-y-2 lg:col-span-2">
          <p className="text-sm font-medium">Mapped credentials</p>
          <div className="divide-border overflow-hidden rounded-md border">
            {mappings.map((mapping) => (
              <div
                key={`${mapping.hostname}:${mapping.path}:${mapping.field}`}
                className="flex items-center justify-between gap-3 px-3 py-2"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">
                    {mapping.hostname}
                  </p>
                  <code className="text-muted-foreground text-xs">
                    {mapping.path} · {mapping.field}
                  </code>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="size-8 shrink-0"
                  onClick={() => handleMappingDelete(mapping)}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
            ))}
            {mappings.length === 0 && (
              <p className="text-muted-foreground px-3 py-8 text-center text-xs">
                No mappings configured.
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
