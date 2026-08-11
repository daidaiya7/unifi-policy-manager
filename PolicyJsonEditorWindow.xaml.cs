using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using UniFiDnsManager.Models;
using UniFiDnsManager.Services;

namespace UniFiDnsManager;

public partial class PolicyJsonEditorWindow : Window
{
    private readonly OfficialPolicyKind _kind;
    private readonly OfficialPolicyRule? _existing;
    private bool _initialized;
    public string? ResultJson { get; private set; }

    public PolicyJsonEditorWindow(OfficialPolicyKind kind, IReadOnlyList<PolicyReferenceItem> references, OfficialPolicyRule? existing = null, bool readOnly = false)
    {
        InitializeComponent();
        _kind = kind;
        _existing = existing;
        ReferencesListBox.ItemsSource = references;
        CategoryText.Text = kind == OfficialPolicyKind.Acl ? "ACL RULE · OFFICIAL API" : "FIREWALL POLICY · OFFICIAL API";
        HeadingText.Text = readOnly && existing is not null
            ? $"查看：{existing.Name}"
            : existing is null
            ? (kind == OfficialPolicyKind.Acl ? "新增 ACL 规则" : "新增防火墙策略")
            : $"编辑：{existing.Name}";
        Title = HeadingText.Text;
        TemplatePanel.Visibility = existing is null && kind == OfficialPolicyKind.Acl ? Visibility.Visible : Visibility.Collapsed;
        JsonTextBox.Text = readOnly && existing is not null
            ? existing.RawResponseJson
            : existing?.ToEditableJson() ?? OfficialPolicyJson.CreateTemplate(kind);
        JsonTextBox.IsReadOnly = readOnly;
        SaveButton.Visibility = readOnly ? Visibility.Collapsed : Visibility.Visible;
        _initialized = true;
    }

    private void TemplateComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_initialized || _existing is not null || _kind != OfficialPolicyKind.Acl) return;
        var variant = (TemplateComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "IPV4";
        JsonTextBox.Text = OfficialPolicyJson.CreateTemplate(_kind, variant);
    }

    private void FormatButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var document = JsonDocument.Parse(JsonTextBox.Text);
            JsonTextBox.Text = JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException ex)
        {
            MessageBox.Show(this, ex.Message, "JSON 格式错误", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ReferencesListBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ReferencesListBox.SelectedItem is PolicyReferenceItem item) Clipboard.SetText(item.Id);
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            ResultJson = OfficialPolicyJson.NormalizeAndValidate(_kind, JsonTextBox.Text);
            DialogResult = true;
        }
        catch (Exception ex) when (ex is ValidationException or JsonException)
        {
            MessageBox.Show(this, ex.Message, "策略请求体有误", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
