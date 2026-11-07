using Windows.Storage;

namespace HotspotShade.WinUI2.Services
{
    // Local Windows settings: the appearance, Let ping work, and the Activity
    // details choice. The store holds no credential and no source device
    // data.
    public sealed class LocalSettingsStore
    {
        private readonly ApplicationDataContainer container;

        public LocalSettingsStore()
        {
            try
            {
                container = ApplicationData.Current.LocalSettings;
            }
            catch
            {
                container = null;
            }
        }

        public string Read(string key)
        {
            if (container == null)
            {
                return null;
            }
            try
            {
                if (container.Values.ContainsKey(key))
                {
                    return container.Values[key] as string;
                }
            }
            catch
            {
                return null;
            }
            return null;
        }

        public void Write(string key, string value)
        {
            if (container == null)
            {
                return;
            }
            try
            {
                container.Values[key] = value;
            }
            catch
            {
                // A settings failure must not stop the window.
            }
        }
    }
}
