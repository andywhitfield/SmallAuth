using System;
using System.ComponentModel.DataAnnotations;

namespace SmallAuth.Attributes
{
    public class ValidateUriListAttribute : ValidationAttribute
    {
        public ValidateUriListAttribute()
        {
        }
        
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var uris = value as string;
            if (string.IsNullOrEmpty(uris))
                return ValidationResult.Success;
            foreach (var uri in uris.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.IsNullOrWhiteSpace(uri))
                    continue;
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var _))
                    return new ValidationResult($"{uri} is not a valid URI.");
            }
            return ValidationResult.Success;
        }
    }
}