using System.Windows;
using System.Windows.Input;
using UniFiDnsManager.Models;

namespace UniFiDnsManager;

public partial class SiteSelectionWindow : Window
{
    public UniFiSite? SelectedSite { get; private set; }

    public SiteSelectionWindow(IReadOnlyList<UniFiSite> sites)
    {
        InitializeComponent();
        SitesListBox.ItemsSource = sites;
        SitesListBox.SelectedIndex = sites.Count > 0 ? 0 : -1;
    }

    private void SelectButton_Click(object sender, RoutedEventArgs e) => AcceptSelection();

    private void SitesListBox_MouseDoubleClick(object sender, MouseButtonEventArgs e) => AcceptSelection();

    private void AcceptSelection()
    {
        if (SitesListBox.SelectedItem is not UniFiSite site)
        {
            MessageBox.Show(this, "请选择一个站点。", "未选择站点", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        SelectedSite = site;
        DialogResult = true;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
