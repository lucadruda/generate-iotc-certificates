declare module "inquirer-file-tree-selection-prompt" {
  import { prompts } from "inquirer";
  class FileTreeSelectionPrompt implements prompts.PromptBase {
    status: PromptState;

    /**
     * Runs the prompt.
     *
     * @returns
     * The result of the prompt.
     */
    run(): Promise<any>;
  }
  export = FileTreeSelectionPrompt;
}
