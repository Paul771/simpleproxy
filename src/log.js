// FILE: src/log.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Single log formatter [proxy][marker] msg -> stdout with redaction guarantee
//   SCOPE: format and write log lines; never receives tunnel data or credentials
//   DEPENDS: none
//   LINKS: M-LOG
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   makeLog - create a log function
// END_MODULE_MAP

// START_CONTRACT: makeLog
//   PURPOSE: Create a log function that writes "[proxy][marker] msg" to stdout
//   INPUTS: { none }
//   OUTPUTS: { (marker: string, ...args: unknown[]) => void }
//   SIDE_EFFECTS: writes to stdout
//   LINKS: M-LOG
// END_CONTRACT: makeLog
export function makeLog() {
  // START_BLOCK_FORMAT
  return (marker, ...args) => {
    const parts = args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a)));
    console.log(`[proxy][${marker}] ${parts.join(" ")}`);
  };
  // END_BLOCK_FORMAT
}
