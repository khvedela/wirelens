import {
  buildProxiedInstance,
  hotkeysCoreFeature,
  selectionFeature,
  syncDataLoaderFeature,
  type Updater,
} from "@headless-tree/core";
import { useTree } from "@headless-tree/react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useMemo, useRef, useState } from "react";

import type { PacketDetail, PacketDetailField } from "./packet-detail-boundary";
import { fieldAccessibleName, formatByteRange, formatFieldValue } from "./packet-detail-model";

const ROOT_ITEM_ID = "wirelens-packet-field-root";
const FIELD_ROW_HEIGHT = 42;

interface FieldTreeNode {
  readonly children: readonly string[];
  readonly field?: PacketDetailField;
  readonly name: string;
}

export interface FieldTreeProps {
  readonly detail: PacketDetail;
  readonly matchedFieldIds: ReadonlySet<number>;
  readonly onFieldSelected: (field: PacketDetailField) => void;
  readonly primaryFieldId: number | null;
}

function itemId(fieldId: number): string {
  return `field-${fieldId}`;
}

function resolveUpdater<T>(updater: Updater<T>, current: T): T {
  return typeof updater === "function" ? (updater as (value: T) => T)(current) : updater;
}

function buildNodes(detail: PacketDetail): ReadonlyMap<string, FieldTreeNode> {
  const children = new Map<number, string[]>();
  const fieldsById = new Map(detail.fields.map((field) => [field.id, field]));
  const rootIds: string[] = [];
  const seenRoots = new Set<number>();

  for (const field of detail.fields) {
    if (field.parentId === null || !fieldsById.has(field.parentId)) continue;
    const siblings = children.get(field.parentId) ?? [];
    siblings.push(itemId(field.id));
    children.set(field.parentId, siblings);
  }

  for (const layer of detail.layers) {
    const rootFieldId = layer.rootFieldId;
    if (rootFieldId === null || seenRoots.has(rootFieldId) || !fieldsById.has(rootFieldId))
      continue;
    seenRoots.add(rootFieldId);
    rootIds.push(itemId(rootFieldId));
  }
  for (const field of detail.fields) {
    if (field.parentId !== null || seenRoots.has(field.id)) continue;
    seenRoots.add(field.id);
    rootIds.push(itemId(field.id));
  }

  const nodes = new Map<string, FieldTreeNode>();
  nodes.set(ROOT_ITEM_ID, { children: rootIds, name: "Decoded fields" });
  for (const field of detail.fields) {
    nodes.set(itemId(field.id), {
      children: children.get(field.id) ?? [],
      field,
      name: fieldAccessibleName(field),
    });
  }
  return nodes;
}

function rootExpansionIds(nodes: ReadonlyMap<string, FieldTreeNode>): string[] {
  const root = nodes.get(ROOT_ITEM_ID);
  if (root === undefined) return [];
  return root.children.filter((id) => (nodes.get(id)?.children.length ?? 0) > 0);
}

function expandedAncestors(
  detail: PacketDetail,
  matchedFieldIds: ReadonlySet<number>,
): readonly string[] {
  const fields = new Map(detail.fields.map((field) => [field.id, field]));
  const result = new Set<string>();
  for (const fieldId of matchedFieldIds) {
    let parentId = fields.get(fieldId)?.parentId ?? null;
    let remaining = detail.fields.length;
    while (parentId !== null && remaining > 0) {
      result.add(itemId(parentId));
      parentId = fields.get(parentId)?.parentId ?? null;
      remaining -= 1;
    }
  }
  return [...result];
}

export function FieldTree({
  detail,
  matchedFieldIds,
  onFieldSelected,
  primaryFieldId,
}: FieldTreeProps) {
  const nodes = useMemo(() => buildNodes(detail), [detail]);
  const [expandedItems, setExpandedItems] = useState<string[]>(() => rootExpansionIds(nodes));
  const scrollElement = useRef<HTMLDivElement>(null);
  const scrollToIndex = useRef<(index: number) => void>(() => undefined);
  const selectedItems = useMemo(
    () => [...matchedFieldIds].map(itemId).filter((id) => nodes.has(id)),
    [matchedFieldIds, nodes],
  );

  useEffect(() => {
    setExpandedItems((current) => [
      ...new Set([
        ...current,
        ...rootExpansionIds(nodes),
        ...expandedAncestors(detail, matchedFieldIds),
      ]),
    ]);
  }, [detail, matchedFieldIds, nodes]);

  const tree = useTree<FieldTreeNode>({
    dataLoader: {
      getChildren: (id) => [...(nodes.get(id)?.children ?? [])],
      getItem: (id) => nodes.get(id) ?? { children: [], name: "Unknown field" },
    },
    features: [syncDataLoaderFeature, selectionFeature, hotkeysCoreFeature],
    getItemName: (item) => item.getItemData().name,
    instanceBuilder: buildProxiedInstance,
    isItemFolder: (item) => item.getItemData().children.length > 0,
    onPrimaryAction: (item) => {
      const field = item.getItemData().field;
      if (field !== undefined) onFieldSelected(field);
    },
    rootItemId: ROOT_ITEM_ID,
    scrollToItem: (item) => scrollToIndex.current(item.getItemMeta().index),
    setExpandedItems: (updater) =>
      setExpandedItems((current) => [...new Set(resolveUpdater(updater, current))]),
    // Selection is owned by the correlation result. Primary actions update it
    // through onFieldSelected; modifier-key selection cannot create a range
    // that has no byte-level meaning.
    setSelectedItems: () => undefined,
    state: { expandedItems, selectedItems },
  });
  const items = tree.getItems();
  const virtualizer = useVirtualizer({
    count: items.length,
    estimateSize: () => FIELD_ROW_HEIGHT,
    getItemKey: (index) => items[index]?.getId() ?? index,
    getScrollElement: () => scrollElement.current,
    overscan: 8,
    useFlushSync: false,
  });
  scrollToIndex.current = (index) => virtualizer.scrollToIndex(index, { align: "auto" });
  const virtualItems = virtualizer.getVirtualItems();
  const focusedItemIsRendered = virtualItems.some(
    ({ index }) => items[index]?.isFocused() === true,
  );
  const fallbackFocusableIndex = virtualItems.find(
    ({ index }) => items[index]?.getItemData().field !== undefined,
  )?.index;

  useEffect(() => {
    if (primaryFieldId === null) return;
    const index = items.findIndex((item) => item.getId() === itemId(primaryFieldId));
    if (index >= 0) virtualizer.scrollToIndex(index, { align: "auto" });
  }, [items, primaryFieldId, virtualizer]);

  const containerProps = tree.getContainerProps("Decoded packet fields");
  const treeRef = containerProps.ref as ((element: HTMLElement | null) => void) | undefined;
  const { ref: _treeRef, ...renderedContainerProps } = containerProps;

  if (detail.fields.length === 0) {
    return <p className="packet-detail-empty">No decoded fields are available for this packet.</p>;
  }

  return (
    <div ref={scrollElement} className="field-tree__viewport" data-testid="field-tree-viewport">
      <div
        {...renderedContainerProps}
        ref={treeRef}
        className="field-tree"
        style={{ blockSize: `${virtualizer.getTotalSize()}px` }}
      >
        {virtualItems.map((virtualItem) => {
          const item = items[virtualItem.index];
          if (item === undefined) return null;
          const node = item.getItemData();
          const field = node.field;
          if (field === undefined) return null;
          const props = item.getProps();
          const itemRef = props.ref as ((element: HTMLElement | null) => void) | undefined;
          const { ref: _itemRef, ...renderedProps } = props;
          const isPrimary = field.id === primaryFieldId;
          const isMatched = matchedFieldIds.has(field.id);
          const value = formatFieldValue(field.value);
          return (
            <button
              {...renderedProps}
              ref={itemRef}
              className="field-tree__row"
              data-field-id={field.id}
              data-focused={item.isFocused()}
              data-index={virtualItem.index}
              data-matched={isMatched}
              data-primary={isPrimary}
              key={virtualItem.key}
              aria-label={`${node.name}${isPrimary ? ", primary match" : isMatched ? ", overlapping match" : ""}`}
              tabIndex={
                item.isFocused() ||
                (!focusedItemIsRendered && virtualItem.index === fallbackFocusableIndex)
                  ? 0
                  : -1
              }
              style={{
                blockSize: `${virtualItem.size}px`,
                paddingInlineStart: `${0.7 + item.getItemMeta().level * 1.05}rem`,
                transform: `translateY(${virtualItem.start}px)`,
              }}
              type="button"
            >
              <span className="field-tree__disclosure" aria-hidden="true">
                {item.isFolder() ? (item.isExpanded() ? "▾" : "▸") : "·"}
              </span>
              <span className="field-tree__name">{field.name}</span>
              {value.length === 0 ? null : (
                <span className="field-tree__value" dir="auto">
                  {value}
                </span>
              )}
              <span className="field-tree__range">{formatByteRange(field.byteRange)}</span>
              {isPrimary ? <span className="field-tree__match-label">Primary</span> : null}
              {!isPrimary && isMatched ? (
                <span className="field-tree__match-label">Also overlaps</span>
              ) : null}
            </button>
          );
        })}
      </div>
    </div>
  );
}
