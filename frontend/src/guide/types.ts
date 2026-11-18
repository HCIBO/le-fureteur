export type Block =
  | { p: string }
  | { ul: string[] }
  | { ol: string[] }
  | { table: { head: string[]; rows: string[][] } }
  | { code: string }
  | { note: string };

export type Section = { id: string; title: string; blocks: Block[] };

export type GuideContent = {
  intro: string;
  sections: Section[];
  api: {
    title: string;
    groupsHead: [string, string, string];
    groups: [string, string, string][];
    fullListTitle: string;
    fullListNote: string;
  };
};
