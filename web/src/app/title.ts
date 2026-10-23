import { useEffect } from "react";

import { PRODUCT_NAME } from "./product";

/** Sets the document title for the current page. */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} · ${PRODUCT_NAME}`;
  }, [title]);
}
