using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace UCASecurity.Web.ViewModels
{
    public class ItemViewModel
    {
        public ItemViewModel()
        {
            HasInfo = true;
        }
        public string Title { get; set; }
        public bool Healthy { get; set; }
        public string Controller { get; set; }
        public string Action { get; set; }
        public string Image { get; set; }
        public bool HasInfo { get; set; }
    }
}
