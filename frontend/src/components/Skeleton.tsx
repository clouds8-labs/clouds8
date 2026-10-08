// Loading Kit, ported from the design-kit mockup page: a skeleton always has
// the shape/height of the content it becomes, so nothing shifts when a row
// resolves. Rows keep their position until a run ends - callers are
// responsible for not reordering while skeletons are present.

export function SkeletonBar({ width = "100%" }: { width?: string }) {
  return <div className="lm-skeleton h-3" style={{ width }} />;
}

export function SkeletonLines({ widths = ["100%", "82%", "64%"] }: { widths?: string[] }) {
  return (
    <div className="flex flex-col gap-[11px]">
      {widths.map((w, i) => (
        <SkeletonBar key={i} width={w} />
      ))}
    </div>
  );
}

export function SkeletonStatTile() {
  return (
    <div className="rounded-lg border border-lm-line bg-lm-panel p-4">
      <div className="lm-skeleton h-3 w-20 mb-3" />
      <div className="lm-skeleton h-7 w-16" />
    </div>
  );
}

// 58px tall - identical to a resolved asset row, so the table never jumps
// when the row fills in.
export function SkeletonAssetRow({ columns = 6 }: { columns?: number }) {
  return (
    <tr className="border-b border-lm-line" style={{ height: 58 }}>
      <td className="px-4">
        <div className="lm-skeleton h-3 w-3 rounded-sm" />
      </td>
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-4">
          <div className="lm-skeleton h-3" style={{ width: i === 0 ? "70%" : "50%" }} />
        </td>
      ))}
    </tr>
  );
}
