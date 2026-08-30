/* The Dashboard tab: currently a placeholder. Registered like every other
   page module so tab switching, refresh scheduling and the "reload lands
   back on this tab" behavior all work the same way here as everywhere
   else, even though there is nothing to fetch yet. */
(() => {
  function init() {}
  async function refresh() {}

  App.pages.dashboard = { init, refresh };
})();
