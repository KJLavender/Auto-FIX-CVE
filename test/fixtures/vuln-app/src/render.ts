import _ from "lodash";
import { merge } from "lodash";

export function render(userTemplate: string, data: object) {
  const compiled = _.template(userTemplate);
  return compiled(merge({}, data));
}
